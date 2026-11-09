// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading MCP JSON-RPC requests, so a rule can limit which tools an agent
//! calls. Only the method and tool name are read; arguments are never
//! inspected or logged.

use serde_json::Value;

/// One JSON-RPC message in a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpMessage {
    /// The request id, `None` for notifications.
    pub id: Option<Value>,
    pub method: String,
    /// `params.name` of a `tools/call`.
    pub tool: Option<String>,
}

/// Why a body could not be read as MCP JSON-RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotJsonRpc(pub String);

fn message(value: &Value) -> Result<Option<McpMessage>, NotJsonRpc> {
    let Some(object) = value.as_object() else {
        return Err(NotJsonRpc(
            "a JSON-RPC message must be a JSON object".into(),
        ));
    };
    // Responses to server requests carry no method; they call no tool.
    let Some(method) = object.get("method") else {
        return Ok(None);
    };
    let method = method
        .as_str()
        .ok_or_else(|| NotJsonRpc("'method' must be a string".into()))?
        .to_string();
    let tool = if method == "tools/call" {
        let name = object
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| NotJsonRpc("a tools/call needs params.name as a string".into()))?;
        Some(name.to_string())
    } else {
        None
    };
    Ok(Some(McpMessage {
        id: object.get("id").cloned(),
        method,
        tool,
    }))
}

/// The messages in a single message or a batch.
pub fn messages(body: &[u8]) -> Result<Vec<McpMessage>, NotJsonRpc> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| NotJsonRpc(format!("the body is not JSON: {e}")))?;
    let items = match &value {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        other => vec![other],
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if let Some(m) = message(item)? {
            out.push(m);
        }
    }
    Ok(out)
}

/// The JSON-RPC error returned for a refused call, naming the tool.
pub fn refusal(id: Option<&Value>, tool: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": -32001,
            "message": format!(
                "tool '{tool}' is not allowed by this session's rule; ask an admin to add it to the rule's allowed tools"
            ),
            "data": { "tool": tool, "reason": "not_allowed" },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_messages_batches_and_responses() {
        let one = messages(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}"#).unwrap();
        assert_eq!(
            one,
            vec![McpMessage {
                id: Some(Value::from(1)),
                method: "tools/call".into(),
                tool: Some("search".into()),
            }]
        );
        let batch = messages(
            br#"[{"jsonrpc":"2.0","id":"a","method":"tools/list"},
                 {"jsonrpc":"2.0","method":"notifications/initialized"},
                 {"jsonrpc":"2.0","id":7,"result":{}}]"#,
        )
        .unwrap();
        assert_eq!(
            batch.len(),
            2,
            "the response to a server request is skipped"
        );
        assert_eq!(batch[0].tool, None);
        assert_eq!(batch[1].id, None);
    }

    #[test]
    fn malformed_bodies_explain_themselves() {
        assert!(messages(b"not json").unwrap_err().0.contains("not JSON"));
        assert!(messages(b"[1]").unwrap_err().0.contains("object"));
        assert!(messages(br#"{"method":5}"#)
            .unwrap_err()
            .0
            .contains("string"));
        assert!(messages(br#"{"method":"tools/call","params":{}}"#)
            .unwrap_err()
            .0
            .contains("params.name"));
    }

    #[test]
    fn refusals_name_the_tool_and_echo_the_id() {
        let r = refusal(Some(&Value::from("req-1")), "delete_repo");
        assert_eq!(r["id"], "req-1");
        assert_eq!(r["error"]["data"]["tool"], "delete_repo");
        assert!(r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("delete_repo"));
        assert_eq!(refusal(None, "x")["id"], Value::Null);
    }
}
