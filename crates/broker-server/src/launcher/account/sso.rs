// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use tokenless_control::service::auth::CliLoginStarted;

pub struct BrowserSignIn {
    pub url: String,
    pub confirmation: String,
    base: String,
    device_code: Zeroizing<String>,
    purpose: SignInFor,
    deadline: tokio::time::Instant,
}
pub(super) fn secure_base(server: &str) -> Result<String, LauncherError> {
    let base = normalise(server)?;
    let url = url::Url::parse(&base)
        .map_err(|_| LauncherError::config("the sign-in server URL is invalid"))?;
    let local = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        host => host == Some(url::Host::Domain("localhost")),
    };
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LauncherError::config("this operation requires HTTPS (HTTP only on loopback), without URL credentials, query or fragment"));
    }
    Ok(base)
}
pub(super) async fn checked(
    response: reqwest::Response,
) -> Result<reqwest::Response, LauncherError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let problem = Problem::read(response).await;
    Err(LauncherError::Api {
        operation: "signing in with single sign-on",
        status,
        title: problem.title,
        detail: problem.detail,
    })
}
pub async fn begin_browser_sign_in(
    server: &str,
    provider: &str,
    purpose: SignInFor,
) -> Result<BrowserSignIn, LauncherError> {
    let base = secure_base(server)?;
    let endpoint = format!("{base}/api/v1/auth/cli/start");
    let response = http_client(&base)?
        .post(&endpoint)
        .json(&json!({"provider":provider,"manage":purpose == SignInFor::Manage}))
        .send()
        .await
        .map_err(|e| LauncherError::Http {
            operation: "starting browser sign-in",
            url: endpoint.clone(),
            reason: e.to_string(),
        })?;
    let started: CliLoginStarted =
        checked(response)
            .await?
            .json()
            .await
            .map_err(|e| LauncherError::Http {
                operation: "reading browser sign-in",
                url: endpoint,
                reason: e.to_string(),
            })?;
    let back = format!(
        "/#/cli-login?code={}",
        url::form_urlencoded::byte_serialize(started.user_code.as_bytes()).collect::<String>()
    );
    let slug: String = url::form_urlencoded::byte_serialize(provider.as_bytes()).collect();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", &back)
        .finish();
    Ok(BrowserSignIn {
        url: format!("{base}/api/v1/auth/oidc/{slug}/start?{query}"),
        confirmation: started.user_code,
        base,
        device_code: Zeroizing::new(started.device_code),
        purpose,
        deadline: tokio::time::Instant::now() + Duration::from_secs(started.expires_in.min(300)),
    })
}
#[derive(Deserialize)]
struct Ready {
    token: String,
    csrf_token: String,
    user: UserSummary,
    expires_at: DateTime<Utc>,
}
impl BrowserSignIn {
    pub async fn wait(self) -> Result<SavedSession, LauncherError> {
        let endpoint = format!("{}/api/v1/auth/cli/poll", self.base);
        let client = http_client(&self.base)?;
        let polling = async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let response = client
                    .post(&endpoint)
                    .json(&json!({"device_code":self.device_code.as_str()}))
                    .send()
                    .await
                    .map_err(|e| LauncherError::Http {
                        operation: "waiting for browser approval",
                        url: endpoint.clone(),
                        reason: e.to_string(),
                    })?;
                if response.status() == reqwest::StatusCode::ACCEPTED {
                    continue;
                }
                let ready: Ready =
                    checked(response)
                        .await?
                        .json()
                        .await
                        .map_err(|e| LauncherError::Http {
                            operation: "reading browser approval",
                            url: endpoint.clone(),
                            reason: e.to_string(),
                        })?;
                return Ok(SavedSession {
                    server: self.base.clone(),
                    username: ready.user.username,
                    totp_enrolled: ready.user.totp_enrolled,
                    token: ready.token,
                    csrf_token: ready.csrf_token,
                    expires_at: ready.expires_at,
                    manage: self.purpose == SignInFor::Manage,
                });
            }
        };
        tokio::time::timeout_at(self.deadline, polling)
            .await
            .map_err(|_| {
                LauncherError::config(
                    "browser sign-in expired after five minutes; run tokenless login again",
                )
            })?
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_login_requires_tls_except_loopback() {
        for url in [
            "https://broker.example",
            "http://127.0.0.1:8080",
            "http://127.0.0.2:8080",
            "http://127.255.255.254:8080",
            "http://[::1]:8080",
            "http://localhost:8080",
        ] {
            assert!(secure_base(url).is_ok());
        }
        for url in [
            "http://broker.example",
            "http://128.0.0.1",
            "http://[::2]",
            "https://u:p@broker.example",
            "https://broker.example?x=1",
            "https://broker.example/#x",
        ] {
            assert!(secure_base(url).is_err());
        }
    }
}
