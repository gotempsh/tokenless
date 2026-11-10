// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Logs and metrics to an OpenTelemetry collector or provider over
//! OTLP/HTTP, set up from the standard `OTEL_*` variables.
//!
//! Nothing is sent unless an endpoint is set (`OTEL_EXPORTER_OTLP_ENDPOINT`,
//! or `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` / `..._METRICS_ENDPOINT` for one
//! signal), or `OTEL_LOGS_EXPORTER` / `OTEL_METRICS_EXPORTER` is `otlp`,
//! which sends to `http://localhost:4318`. `serve` sends its logs; `node run`
//! sends its logs and the proxy's counters. `OTEL_RESOURCE_ATTRIBUTES` tags
//! everything sent, and `OTEL_SERVICE_NAME` renames the service.
//!
//! The protocol (`http/protobuf`, the default, or `http/json`; gRPC is not
//! built in) and each signal's timeout are read here, as the HTTP client is
//! built here; the exporter reads the rest itself: headers, compression and
//! temporality. `OTEL_METRIC_EXPORT_INTERVAL` sets how often counters are
//! sent (60 s). Exports go through the server's own HTTP client and TLS (the
//! public web PKI, plus the CAs in `OTEL_EXPORTER_OTLP_CERTIFICATE`), on
//! background threads with bounded queues: a slow or unreachable collector
//! drops telemetry, never traffic.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opentelemetry::metrics::{MeterProvider as _, ObservableCounter};
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_http::{HttpClient, HttpError, ResponseBodyTooLarge};
use opentelemetry_otlp::{LogExporter, MetricExporter, Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::resource::TelemetryResourceDetector;
use opentelemetry_sdk::Resource;
use tokenless_dataplane::metrics::Metrics;
use tracing_subscriber::filter::{filter_fn, FilterExt};
use tracing_subscriber::{EnvFilter, Layer};

use crate::webhook_transport::describe;

/// The collector's default, when only `OTEL_*_EXPORTER=otlp` is set.
const DEFAULT_ENDPOINT: &str = "http://localhost:4318";
/// OTLP's default export timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// A collector answers an export with a short status; read no more.
const MAX_REPLY: usize = 1024 * 1024;

/// Which process is sending: it names the service and decides which
/// signals there are.
#[derive(Debug, Clone, Copy)]
pub enum Component<'a> {
    /// `serve`: logs.
    ControlPlane,
    /// `node run`: logs and the proxy's counters, as the node `node_id`
    /// when its identity could be read.
    Proxy { node_id: Option<&'a str> },
}

impl Component<'_> {
    fn service_name(&self) -> &'static str {
        match self {
            Component::ControlPlane => "tokenless",
            Component::Proxy { .. } => "tokenless-proxy",
        }
    }
}

/// How a signal is encoded: `http/protobuf` unless `http/json` is asked for.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum Encoding {
    #[default]
    Protobuf,
    Json,
}

impl Encoding {
    fn protocol(self) -> Protocol {
        match self {
            Encoding::Protobuf => Protocol::HttpBinary,
            Encoding::Json => Protocol::HttpJson,
        }
    }
}

/// What the `OTEL_*` variables ask for.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub logs: bool,
    pub metrics: bool,
    /// Decided here, not left to the exporter: built with JSON support,
    /// it would default to JSON, and OTLP's default is protobuf.
    pub logs_encoding: Encoding,
    pub metrics_encoding: Encoding,
    /// Where each signal goes, for the startup message: scheme, host and
    /// port only, as a path or query may hold an ingest token.
    pub logs_to: String,
    pub metrics_to: String,
    /// `OTEL_SERVICE_NAME`, over the component's own name.
    pub service_name: Option<String>,
    /// `OTEL_RESOURCE_ATTRIBUTES`: the tags on everything sent.
    pub resource: Vec<(String, String)>,
    /// `OTEL_EXPORTER_OTLP_CERTIFICATE`: a PEM file of CAs the collector's
    /// certificate is checked against, besides the public web PKI.
    pub certificate: Option<String>,
    /// How long one export may take: `OTEL_EXPORTER_OTLP_LOGS_TIMEOUT` /
    /// `..._METRICS_TIMEOUT`, or `OTEL_EXPORTER_OTLP_TIMEOUT`, in
    /// milliseconds. The exporter reads the same variables for how long it
    /// retries; the HTTP client is built here, so it needs them too.
    pub logs_timeout: Duration,
    pub metrics_timeout: Duration,
    /// Variables that were set but are not followed, and why.
    pub ignored: Vec<String>,
    /// Sends to this base URL instead of the `OTEL_EXPORTER_OTLP_*`
    /// endpoints. Never read from the environment; tests set it.
    pub endpoint: Option<String>,
}

impl Default for Settings {
    /// Nothing sent.
    fn default() -> Self {
        Self {
            logs: false,
            metrics: false,
            logs_encoding: Encoding::default(),
            metrics_encoding: Encoding::default(),
            logs_to: String::new(),
            metrics_to: String::new(),
            service_name: None,
            resource: Vec::new(),
            certificate: None,
            logs_timeout: DEFAULT_TIMEOUT,
            metrics_timeout: DEFAULT_TIMEOUT,
            ignored: Vec::new(),
            endpoint: None,
        }
    }
}

impl Settings {
    /// Reads the variables through `var`, which returns a variable's value
    /// when it is set and not empty.
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> Self {
        let var = |name: &str| var(name).filter(|v| !v.trim().is_empty());
        let mut settings = Settings::default();
        if var("OTEL_SDK_DISABLED").is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
            return settings;
        }
        let general = var("OTEL_EXPORTER_OTLP_ENDPOINT");
        let mut signal = |name: &str, upper: &str| -> (bool, String, Encoding) {
            let endpoint = var(&format!("OTEL_EXPORTER_OTLP_{upper}_ENDPOINT"));
            let exporter_var = format!("OTEL_{upper}_EXPORTER");
            let wanted = match var(&exporter_var) {
                None => endpoint.is_some() || general.is_some(),
                Some(list) => {
                    let mut otlp = false;
                    for exporter in list.split(',').map(str::trim) {
                        match exporter {
                            "otlp" => otlp = true,
                            "none" => {}
                            other => settings.ignored.push(format!(
                                "{exporter_var}={other} is not supported (only otlp and none)"
                            )),
                        }
                    }
                    otlp
                }
            };
            let protocol_var = format!("OTEL_EXPORTER_OTLP_{upper}_PROTOCOL");
            let protocol = var(&protocol_var)
                .map(|v| (protocol_var.as_str(), v))
                .or_else(|| {
                    var("OTEL_EXPORTER_OTLP_PROTOCOL").map(|v| ("OTEL_EXPORTER_OTLP_PROTOCOL", v))
                });
            let encoding = match protocol.as_ref().map(|(n, v)| (*n, v.trim())) {
                None | Some((_, "http/protobuf")) => Encoding::Protobuf,
                Some((_, "http/json")) => Encoding::Json,
                Some((_, "grpc")) if wanted => {
                    settings.ignored.push(format!(
                        "{name} are not sent: the gRPC protocol is not supported; use http/protobuf (port 4318)"
                    ));
                    return (false, String::new(), Encoding::Protobuf);
                }
                Some((var_name, other)) => {
                    if wanted {
                        settings.ignored.push(format!(
                            "{var_name}={other} is not supported; {name} use http/protobuf"
                        ));
                    }
                    Encoding::Protobuf
                }
            };
            // The exporter refuses a URL it cannot parse, quoting it in the
            // error; checked here instead, so the message names the variable
            // and not the value, which may hold a token.
            let refused = match (&endpoint, &general) {
                (Some(url), _) => url
                    .parse::<http::Uri>()
                    .is_err()
                    .then(|| format!("OTEL_EXPORTER_OTLP_{upper}_ENDPOINT")),
                (None, Some(base)) => exporter_url(base, name)
                    .parse::<http::Uri>()
                    .is_err()
                    .then(|| "OTEL_EXPORTER_OTLP_ENDPOINT".to_string()),
                (None, None) => None,
            };
            if let (true, Some(var_name)) = (wanted, refused) {
                settings.ignored.push(format!(
                    "{name} are not sent: {var_name} is not a valid URL (look for spaces or a line break in it)"
                ));
                return (false, String::new(), encoding);
            }
            let to = endpoint
                .or_else(|| general.clone())
                .unwrap_or_else(|| DEFAULT_ENDPOINT.into());
            (wanted, origin(&to), encoding)
        };
        let (logs, logs_to, logs_encoding) = signal("logs", "LOGS");
        let (metrics, metrics_to, metrics_encoding) = signal("metrics", "METRICS");
        settings.logs = logs;
        settings.metrics = metrics;
        settings.logs_to = logs_to;
        settings.metrics_to = metrics_to;
        settings.logs_encoding = logs_encoding;
        settings.metrics_encoding = metrics_encoding;
        settings.service_name = var("OTEL_SERVICE_NAME").map(|v| v.trim().to_string());
        if let Some(list) = var("OTEL_RESOURCE_ATTRIBUTES") {
            for pair in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                match pair.split_once('=') {
                    Some((key, value)) if !key.trim().is_empty() => settings
                        .resource
                        .push((percent_decode(key.trim()), percent_decode(value.trim()))),
                    _ => settings.ignored.push(format!(
                        "OTEL_RESOURCE_ATTRIBUTES entry {pair:?} is not key=value"
                    )),
                }
            }
        }
        settings.certificate = var("OTEL_EXPORTER_OTLP_CERTIFICATE");
        let mut timeout = |name: &str| {
            let ms = var(name)?;
            match ms.trim().parse::<u64>() {
                Ok(ms) if ms > 0 => Some(Duration::from_millis(ms)),
                _ => {
                    settings
                        .ignored
                        .push(format!("{name}={ms} is not a number of milliseconds"));
                    None
                }
            }
        };
        let general = timeout("OTEL_EXPORTER_OTLP_TIMEOUT").unwrap_or(DEFAULT_TIMEOUT);
        let logs_timeout = timeout("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT").unwrap_or(general);
        let metrics_timeout = timeout("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT").unwrap_or(general);
        settings.logs_timeout = logs_timeout;
        settings.metrics_timeout = metrics_timeout;
        settings
    }

    /// The process environment.
    pub fn from_process_env() -> Self {
        Self::from_env(|name| std::env::var(name).ok())
    }

    fn resource(&self, component: Component<'_>) -> Resource {
        let mut attributes = vec![
            KeyValue::new("service.name", component.service_name()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ];
        if let Component::Proxy {
            node_id: Some(node_id),
        } = component
        {
            attributes.push(KeyValue::new("service.instance.id", node_id.to_string()));
        }
        // Later attributes win: the tags over the defaults, and
        // OTEL_SERVICE_NAME over a service.name among the tags.
        let mut builder = Resource::builder_empty()
            .with_detector(Box::new(TelemetryResourceDetector))
            .with_attributes(attributes)
            .with_attributes(
                self.resource
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            );
        if let Some(name) = &self.service_name {
            builder = builder.with_service_name(name.clone());
        }
        builder.build()
    }
}

/// `scheme://host:port` of an endpoint, without credentials, path or query.
fn origin(endpoint: &str) -> String {
    match url::Url::parse(endpoint.trim()) {
        Ok(url) => url.origin().ascii_serialization(),
        Err(_) => "an endpoint that is not a URL".into(),
    }
}

/// The URL the exporter sends a signal (`logs` or `metrics`) to when only
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set: `base` with `/v1/<signal>` added,
/// as the exporter adds it.
fn exporter_url(base: &str, signal: &str) -> String {
    let base = base.strip_suffix('/').unwrap_or(base);
    format!("{base}/v1/{signal}")
}

/// An exporter error without an endpoint it quotes: the exporter writes
/// `invalid endpoint '<url>': <why>`, and a URL's path or query may hold a
/// token. A quote that does not close loses the rest of the message.
fn without_endpoint(reason: &str) -> String {
    const QUOTED: &str = "invalid endpoint '";
    let Some(start) = reason.find(QUOTED) else {
        return reason.to_string();
    };
    let head = &reason[..start];
    match reason[start + QUOTED.len()..].rfind("': ") {
        Some(end) => format!(
            "{head}invalid endpoint{}",
            &reason[start + QUOTED.len() + end + 1..]
        ),
        None => format!("{head}invalid endpoint"),
    }
}

/// `OTEL_RESOURCE_ATTRIBUTES` values are percent-encoded (`%2C` for a comma).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("OpenTelemetry export needs a Tokio runtime to send from")]
    NoRuntime,
    #[error("reading the OTEL_EXPORTER_OTLP_CERTIFICATE file {path}: {source}")]
    Certificate {
        path: String,
        source: std::io::Error,
    },
    #[error("setting up TLS for the OpenTelemetry exporter: {reason}")]
    Tls { reason: String },
    #[error("setting up the OpenTelemetry {signal} exporter: {reason}")]
    Exporter {
        signal: &'static str,
        reason: String,
    },
}

/// The running exporters. Shut it down before the process exits, so what
/// is queued is sent.
#[derive(Default)]
pub struct Telemetry {
    logs: Option<SdkLoggerProvider>,
    metrics: Option<SdkMeterProvider>,
    /// Kept so their callbacks stay registered.
    instruments: Mutex<Vec<ObservableCounter<u64>>>,
}

impl Telemetry {
    /// Starts the exporters `settings` asks for. Call it inside the Tokio
    /// runtime: exports are sent from it.
    pub fn start(settings: &Settings, component: Component<'_>) -> Result<Self, TelemetryError> {
        let metrics_wanted = settings.metrics && matches!(component, Component::Proxy { .. });
        if !settings.logs && !metrics_wanted {
            return Ok(Self::default());
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| TelemetryError::NoRuntime)?;
        let tls = exporter_tls(settings)?;
        let resource = settings.resource(component);
        let endpoint = |path: &str| {
            settings
                .endpoint
                .as_ref()
                .map(|base| format!("{}/{path}", base.trim_end_matches('/')))
        };
        let mut telemetry = Self::default();
        if settings.logs {
            let mut builder = LogExporter::builder()
                .with_http()
                .with_protocol(settings.logs_encoding.protocol())
                .with_http_client(OtlpHttp::new(runtime.clone(), &tls, settings.logs_timeout)?);
            if let Some(url) = endpoint("v1/logs") {
                builder = builder.with_endpoint(url);
            }
            let exporter = builder.build().map_err(|e| TelemetryError::Exporter {
                signal: "logs",
                reason: without_endpoint(&e.to_string()),
            })?;
            telemetry.logs = Some(
                SdkLoggerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(exporter)
                    .build(),
            );
        }
        if metrics_wanted {
            let mut builder = MetricExporter::builder()
                .with_http()
                .with_protocol(settings.metrics_encoding.protocol())
                .with_http_client(OtlpHttp::new(runtime, &tls, settings.metrics_timeout)?);
            if let Some(url) = endpoint("v1/metrics") {
                builder = builder.with_endpoint(url);
            }
            let exporter = builder.build().map_err(|e| TelemetryError::Exporter {
                signal: "metrics",
                reason: without_endpoint(&e.to_string()),
            })?;
            telemetry.metrics = Some(
                SdkMeterProvider::builder()
                    .with_resource(resource)
                    .with_reader(PeriodicReader::builder(exporter).build())
                    .build(),
            );
        }
        Ok(telemetry)
    }

    pub fn sends_logs(&self) -> bool {
        self.logs.is_some()
    }

    pub fn sends_metrics(&self) -> bool {
        self.metrics.is_some()
    }

    /// A tracing layer that sends the events `filter` lets through as
    /// OpenTelemetry logs, when logs are sent. The exporter's own events
    /// and those of the HTTP stack beneath it stay out: sending them would
    /// feed back into itself.
    pub fn log_layer<S>(&self, filter: EnvFilter) -> Option<impl Layer<S> + Send + Sync + 'static>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        let provider = self.logs.as_ref()?;
        let own = filter_fn(|meta| !is_exporter_noise(meta.target()));
        Some(OpenTelemetryTracingBridge::new(provider).with_filter(filter.and(own)))
    }

    /// Reports the proxy's counters, each as `tokenless.proxy.<name>`, at
    /// every export. Reading them is a relaxed load: nothing on the request
    /// path changes.
    pub fn watch_proxy(&self, counters: Arc<Metrics>) {
        let Some(provider) = &self.metrics else {
            return;
        };
        let meter = provider.meter("tokenless");
        let mut instruments = self
            .instruments
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (index, counter) in counters.counters().iter().enumerate() {
            let name = counter.name.trim_end_matches("_total");
            let source = counters.clone();
            instruments.push(
                meter
                    .u64_observable_counter(format!("tokenless.proxy.{name}"))
                    .with_description(counter.help)
                    .with_callback(move |observer| {
                        if let Some(c) = source.counters().get(index) {
                            observer.observe(c.get(), &[]);
                        }
                    })
                    .build(),
            );
        }
    }

    /// Sends what is queued and stops the exporters, waiting at most for
    /// their timeouts. Failures are logged; they do not fail the exit.
    ///
    /// The work runs on its own thread, not the runtime's blocking pool, so
    /// a caller that stops waiting (dropping the future) can exit at once:
    /// the runtime does not wait for the thread when it shuts down.
    pub async fn shutdown(self) {
        let Self { logs, metrics, .. } = self;
        if logs.is_none() && metrics.is_none() {
            return;
        }
        let (done, finished) = tokio::sync::oneshot::channel::<()>();
        let spawned = std::thread::Builder::new()
            .name("otel-shutdown".into())
            .spawn(move || {
                // Metrics first: their failures still reach the logs.
                if let Some(provider) = metrics {
                    if let Err(e) = provider.shutdown() {
                        tracing::warn!(error = %e, "OpenTelemetry metrics were not all sent at shutdown");
                    }
                }
                if let Some(provider) = logs {
                    if let Err(e) = provider.shutdown() {
                        tracing::warn!(error = %e, "OpenTelemetry logs were not all sent at shutdown");
                    }
                }
                let _ = done.send(());
            });
        match spawned {
            Ok(_) => {
                let _ = finished.await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not start a thread to send the OpenTelemetry data still queued");
            }
        }
    }

    /// Stops without sending what is queued, for a process told to stop at
    /// once. Dropping the exporters would send it, waiting up to their
    /// timeouts, so they are leaked instead; the process is about to exit.
    pub fn abandon(self) {
        std::mem::forget(self);
    }

    /// Sends what is queued now. Blocks: call it off the runtime's threads.
    #[cfg(test)]
    fn flush(&self) {
        if let Some(p) = &self.logs {
            let _ = p.force_flush();
        }
        if let Some(p) = &self.metrics {
            let _ = p.force_flush();
        }
    }
}

/// The exporter and the HTTP stack it sends through.
fn is_exporter_noise(target: &str) -> bool {
    [
        "opentelemetry",
        "reqwest",
        "hyper",
        "h2",
        "rustls",
        "tokio_rustls",
    ]
    .iter()
    .any(|prefix| target.starts_with(prefix))
}

/// The exporter's HTTP client: the server's reqwest and rustls. Exports
/// come from the SDK's background threads; each request runs on the Tokio
/// runtime and the thread waits for its answer.
#[derive(Debug, Clone)]
struct OtlpHttp {
    http: reqwest::Client,
    runtime: tokio::runtime::Handle,
    timeout: Duration,
}

/// The collector's certificate is checked against the public web PKI and
/// the CAs in `OTEL_EXPORTER_OTLP_CERTIFICATE`.
fn exporter_tls(settings: &Settings) -> Result<rustls::ClientConfig, TelemetryError> {
    let mut roots = Vec::new();
    if let Some(path) = &settings.certificate {
        let pem = std::fs::read_to_string(path).map_err(|source| TelemetryError::Certificate {
            path: path.clone(),
            source,
        })?;
        roots = tokenless_dataplane::tls::certs_from_pem(path, &pem).map_err(|e| {
            TelemetryError::Tls {
                reason: e.to_string(),
            }
        })?;
    }
    let tls = tokenless_dataplane::tls::upstream_client_config(true, &roots).map_err(|e| {
        TelemetryError::Tls {
            reason: e.to_string(),
        }
    })?;
    Ok((*tls).clone())
}

impl OtlpHttp {
    /// A client for one signal, whose exports may take `timeout` each.
    fn new(
        runtime: tokio::runtime::Handle,
        tls: &rustls::ClientConfig,
        timeout: Duration,
    ) -> Result<Self, TelemetryError> {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls.clone())
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(concat!("tokenless/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| TelemetryError::Tls {
                reason: describe(e, timeout),
            })?;
        Ok(Self {
            http,
            runtime,
            timeout,
        })
    }
}

/// Why an export could not be sent, without the endpoint's URL.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct ExportFailed(String);

#[async_trait]
impl HttpClient for OtlpHttp {
    async fn send_bytes(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let http = self.http.clone();
        let timeout = self.timeout;
        self.runtime
            .spawn(async move {
                let fail = |e: reqwest::Error| -> HttpError {
                    Box::new(ExportFailed(describe(e, timeout)))
                };
                let request = reqwest::Request::try_from(request).map_err(fail)?;
                let mut response = http.execute(request).await.map_err(fail)?;
                let mut reply = http::Response::builder().status(response.status());
                for (name, value) in response.headers() {
                    reply = reply.header(name, value);
                }
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(fail)? {
                    if body.len() + chunk.len() > MAX_REPLY {
                        return Err(Box::new(ResponseBodyTooLarge::new()) as HttpError);
                    }
                    body.extend_from_slice(&chunk);
                }
                reply
                    .body(Bytes::from(body))
                    .map_err(|e| Box::new(e) as HttpError)
            })
            .await
            .map_err(|e| -> HttpError { Box::new(ExportFailed(format!("export task: {e}"))) })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{any_value, KeyValue as ProtoKeyValue};
    use opentelemetry_proto::tonic::metrics::v1::{metric, number_data_point};
    use prost::Message;
    use tracing_subscriber::layer::SubscriberExt;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn nothing_is_sent_without_an_endpoint() {
        let s = Settings::from_env(env(&[("OTEL_RESOURCE_ATTRIBUTES", "team=platform")]));
        assert!(!s.logs && !s.metrics);
        assert!(s.ignored.is_empty());
    }

    #[test]
    fn an_endpoint_sends_both_and_says_where_without_secrets() {
        let s = Settings::from_env(env(&[(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "https://user:secret@otlp.example.com:4318/otlp?token=abc",
        )]));
        assert!(s.logs && s.metrics);
        assert_eq!(s.logs_to, "https://otlp.example.com:4318");
        assert_eq!(s.metrics_to, "https://otlp.example.com:4318");
    }

    #[test]
    fn a_signal_endpoint_or_exporter_turns_on_only_that_signal() {
        let s = Settings::from_env(env(&[(
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            "http://collector:4318/v1/logs",
        )]));
        assert!(s.logs && !s.metrics);
        assert_eq!(s.logs_to, "http://collector:4318");

        let s = Settings::from_env(env(&[("OTEL_METRICS_EXPORTER", "otlp")]));
        assert!(!s.logs && s.metrics);
        assert_eq!(s.metrics_to, "http://localhost:4318");
    }

    #[test]
    fn none_disabled_and_unsupported_values_turn_signals_off() {
        let endpoint = ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318");
        let s = Settings::from_env(env(&[endpoint, ("OTEL_LOGS_EXPORTER", "none")]));
        assert!(!s.logs && s.metrics);

        let s = Settings::from_env(env(&[endpoint, ("OTEL_SDK_DISABLED", "TRUE")]));
        assert!(!s.logs && !s.metrics);

        let s = Settings::from_env(env(&[endpoint, ("OTEL_METRICS_EXPORTER", "console")]));
        assert!(s.logs && !s.metrics);
        assert_eq!(
            s.ignored,
            ["OTEL_METRICS_EXPORTER=console is not supported (only otlp and none)"]
        );

        let s = Settings::from_env(env(&[endpoint, ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")]));
        assert!(!s.logs && !s.metrics);
        assert!(
            s.ignored[0].contains("gRPC protocol is not supported"),
            "{:?}",
            s.ignored
        );
    }

    #[test]
    fn protobuf_unless_json_is_asked_for_per_signal_or_overall() {
        let endpoint = ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318");
        let s = Settings::from_env(env(&[endpoint]));
        assert_eq!(
            (s.logs_encoding, s.metrics_encoding),
            (Encoding::Protobuf, Encoding::Protobuf)
        );

        let s = Settings::from_env(env(&[
            endpoint,
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/protobuf"),
        ]));
        assert_eq!(
            (s.logs_encoding, s.metrics_encoding),
            (Encoding::Json, Encoding::Protobuf)
        );

        let s = Settings::from_env(env(&[
            endpoint,
            ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "thrift"),
        ]));
        assert_eq!(s.logs_encoding, Encoding::Protobuf);
        assert_eq!(
            s.ignored,
            ["OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=thrift is not supported; logs use http/protobuf"]
        );
    }

    #[test]
    fn resource_attributes_are_parsed_and_decoded() {
        let s = Settings::from_env(env(&[(
            "OTEL_RESOURCE_ATTRIBUTES",
            "team=platform, deployment.environment.name=prod ,note=a%2Cb%3Dc,broken",
        )]));
        assert_eq!(
            s.resource,
            [
                ("team".to_string(), "platform".to_string()),
                ("deployment.environment.name".into(), "prod".into()),
                ("note".into(), "a,b=c".into()),
            ]
        );
        assert_eq!(
            s.ignored,
            ["OTEL_RESOURCE_ATTRIBUTES entry \"broken\" is not key=value"]
        );
    }

    #[test]
    fn a_bad_timeout_is_ignored_and_said() {
        let d = Settings::default();
        assert_eq!(
            (d.logs_timeout, d.metrics_timeout),
            (DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
        );
        let s = Settings::from_env(env(&[("OTEL_EXPORTER_OTLP_TIMEOUT", "2500")]));
        let ms = Duration::from_millis;
        assert_eq!((s.logs_timeout, s.metrics_timeout), (ms(2500), ms(2500)));
        let s = Settings::from_env(env(&[("OTEL_EXPORTER_OTLP_TIMEOUT", "soon")]));
        assert_eq!(s.logs_timeout, DEFAULT_TIMEOUT);
        assert_eq!(
            s.ignored,
            ["OTEL_EXPORTER_OTLP_TIMEOUT=soon is not a number of milliseconds"]
        );
    }

    #[test]
    fn a_signal_timeout_overrides_the_general_one_for_that_signal() {
        let ms = Duration::from_millis;
        let s = Settings::from_env(env(&[
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
            ("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "30000"),
        ]));
        assert_eq!((s.logs_timeout, s.metrics_timeout), (ms(2500), ms(30000)));
        let s = Settings::from_env(env(&[("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "2000")]));
        assert_eq!(
            (s.logs_timeout, s.metrics_timeout),
            (ms(2000), DEFAULT_TIMEOUT)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_signal_waits_for_the_collector_as_long_as_its_own_timeout() {
        // A collector that accepts the connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let tls = exporter_tls(&Settings::default()).unwrap();
        let runtime = tokio::runtime::Handle::current();
        let send = |timeout: Duration| {
            let client = OtlpHttp::new(runtime.clone(), &tls, timeout).unwrap();
            let request = http::Request::post(format!("{base}/v1/logs"))
                .body(Bytes::new())
                .unwrap();
            async move {
                let started = std::time::Instant::now();
                let result = client.send_bytes(request).await;
                (result.map(|_| ()), started.elapsed())
            }
        };
        let (short, long) = tokio::join!(
            send(Duration::from_millis(200)),
            send(Duration::from_millis(1500))
        );
        let (short_result, short_took) = short;
        let (long_result, long_took) = long;
        assert!(short_result.is_err() && long_result.is_err());
        assert!(short_took < Duration::from_millis(1000), "{short_took:?}");
        assert!(long_took >= Duration::from_millis(1400), "{long_took:?}");
    }

    #[test]
    fn an_endpoint_the_exporter_would_refuse_is_named_but_never_quoted() {
        let secret = "https://user:secret@otlp.example.com/otlp?token=abc\n";
        let s = Settings::from_env(env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", secret)]));
        assert!(!s.logs && !s.metrics);
        assert_eq!(s.ignored.len(), 2, "{:?}", s.ignored);
        assert!(
            s.ignored[0]
                .starts_with("logs are not sent: OTEL_EXPORTER_OTLP_ENDPOINT is not a valid URL"),
            "{:?}",
            s.ignored
        );
        let s = Settings::from_env(env(&[(
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            " https://otlp.example.com/v1/metrics?token=abc",
        )]));
        assert!(!s.metrics);
        assert!(s.ignored[0].contains("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"));
        for message in &s.ignored {
            assert!(!message.contains("secret") && !message.contains("token=abc"));
        }
        // A trailing slash is fine, as it is for the exporter.
        let s = Settings::from_env(env(&[(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://collector:4318/",
        )]));
        assert!(s.logs && s.metrics && s.ignored.is_empty());
        assert_eq!(
            exporter_url("http://collector:4318/", "logs"),
            "http://collector:4318/v1/logs"
        );
    }

    #[test]
    fn exporter_errors_lose_the_endpoint_they_quote() {
        assert_eq!(
            without_endpoint(
                "invalid exporter configuration: OTEL_EXPORTER_OTLP_ENDPOINT: invalid endpoint 'https://u:secret@h/?token=a': b': invalid uri character"
            ),
            "invalid exporter configuration: OTEL_EXPORTER_OTLP_ENDPOINT: invalid endpoint: invalid uri character"
        );
        assert_eq!(
            without_endpoint(
                "invalid exporter configuration: endpoint: invalid endpoint 'https://h/?token=a"
            ),
            "invalid exporter configuration: endpoint: invalid endpoint"
        );
        let other = "invalid exporter configuration: compression: zstd compression requested but zstd-http feature not enabled";
        assert_eq!(without_endpoint(other), other);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_stop_at_once_does_not_wait_for_the_collector() {
        // A collector that accepts the connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let start = || {
            let settings = Settings {
                endpoint: Some(base.clone()),
                logs_timeout: Duration::from_secs(30),
                ..Settings::from_env(env(&[("OTEL_LOGS_EXPORTER", "otlp")]))
            };
            let telemetry = Telemetry::start(&settings, Component::ControlPlane).unwrap();
            let subscriber =
                tracing_subscriber::registry().with(telemetry.log_layer(EnvFilter::new("info")));
            tracing::subscriber::with_default(subscriber, || tracing::info!("never answered"));
            telemetry
        };

        let started = std::time::Instant::now();
        start().abandon();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        // Waiting on the flush can be given up, and nothing then holds the
        // runtime up.
        let started = std::time::Instant::now();
        let gave_up = tokio::time::timeout(Duration::from_millis(200), start().shutdown()).await;
        assert!(
            gave_up.is_err(),
            "the never-answering collector cannot be flushed to"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    fn resource_value(resource: &Resource, key: &'static str) -> Option<String> {
        resource
            .get(&opentelemetry::Key::from_static_str(key))
            .map(|v| v.to_string())
    }

    #[test]
    fn the_service_is_named_by_component_then_tags_then_otel_service_name() {
        let proxy = Component::Proxy {
            node_id: Some("node-7"),
        };
        let r = Settings::default().resource(Component::ControlPlane);
        assert_eq!(
            resource_value(&r, "service.name").as_deref(),
            Some("tokenless")
        );
        assert_eq!(resource_value(&r, "service.instance.id"), None);

        let r = Settings::default().resource(proxy);
        assert_eq!(
            resource_value(&r, "service.name").as_deref(),
            Some("tokenless-proxy")
        );
        assert_eq!(
            resource_value(&r, "service.instance.id").as_deref(),
            Some("node-7")
        );
        assert_eq!(
            resource_value(&r, "service.version").as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );

        let tagged = Settings::from_env(env(&[(
            "OTEL_RESOURCE_ATTRIBUTES",
            "service.name=edge,team=platform",
        )]));
        let r = tagged.resource(proxy);
        assert_eq!(resource_value(&r, "service.name").as_deref(), Some("edge"));
        assert_eq!(resource_value(&r, "team").as_deref(), Some("platform"));

        let named = Settings {
            service_name: Some("proxy-eu".into()),
            ..tagged
        };
        let r = named.resource(proxy);
        assert_eq!(
            resource_value(&r, "service.name").as_deref(),
            Some("proxy-eu")
        );
    }

    #[tokio::test]
    async fn without_settings_nothing_starts_and_serve_sends_no_metrics() {
        let off = Telemetry::start(&Settings::default(), Component::ControlPlane).unwrap();
        assert!(!off.sends_logs() && !off.sends_metrics());
        let both = Settings::from_env(env(&[(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://127.0.0.1:1",
        )]));
        let serve = Telemetry::start(&both, Component::ControlPlane).unwrap();
        assert!(serve.sends_logs() && !serve.sends_metrics());
        serve.shutdown().await;
    }

    type Received = Arc<Mutex<Vec<(String, Bytes)>>>;

    /// A collector that keeps what it is sent.
    async fn collector() -> (String, Received) {
        let received: Received = Arc::default();
        let keep = |path: &'static str, received: Received| {
            axum::routing::post(move |body: Bytes| async move {
                received.lock().unwrap().push((path.to_string(), body));
                ""
            })
        };
        let app = axum::Router::new()
            .route("/v1/logs", keep("/v1/logs", received.clone()))
            .route("/v1/metrics", keep("/v1/metrics", received.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        (format!("http://{addr}"), received)
    }

    fn string(attrs: &[ProtoKeyValue], key: &str) -> Option<String> {
        attrs.iter().find(|kv| kv.key == key).and_then(|kv| {
            match kv.value.as_ref()?.value.as_ref()? {
                any_value::Value::StringValue(s) => Some(s.clone()),
                _ => None,
            }
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn logs_and_proxy_counters_reach_the_collector_with_the_tags() {
        let (base, received) = collector().await;
        let settings = Settings {
            endpoint: Some(base.clone()),
            ..Settings::from_env(env(&[
                (
                    "OTEL_EXPORTER_OTLP_ENDPOINT",
                    "http://collector.invalid:4318",
                ),
                ("OTEL_RESOURCE_ATTRIBUTES", "team=platform"),
            ]))
        };
        let telemetry = Telemetry::start(
            &settings,
            Component::Proxy {
                node_id: Some("node-1"),
            },
        )
        .unwrap();
        let subscriber =
            tracing_subscriber::registry().with(telemetry.log_layer(EnvFilter::new("info")));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(vault = "ops", "a credential was added");
            tracing::info!(target: "reqwest::connect", "the HTTP stack's own event");
            tracing::debug!("below the filter");
        });
        let counters = Arc::new(Metrics::default());
        Metrics::add(&counters.requests_injected_total, 3);
        telemetry.watch_proxy(counters);
        let telemetry = tokio::task::spawn_blocking(move || {
            telemetry.flush();
            telemetry
        })
        .await
        .unwrap();

        let received = received.lock().unwrap().clone();
        let logs: Vec<_> = received
            .iter()
            .filter(|(path, _)| path == "/v1/logs")
            .flat_map(|(_, body)| {
                ExportLogsServiceRequest::decode(body.clone())
                    .unwrap()
                    .resource_logs
            })
            .collect();
        let resource = logs[0].resource.as_ref().unwrap();
        assert_eq!(
            string(&resource.attributes, "service.name").as_deref(),
            Some("tokenless-proxy")
        );
        assert_eq!(
            string(&resource.attributes, "service.instance.id").as_deref(),
            Some("node-1")
        );
        assert_eq!(
            string(&resource.attributes, "team").as_deref(),
            Some("platform")
        );
        let records: Vec<_> = logs
            .iter()
            .flat_map(|r| &r.scope_logs)
            .flat_map(|s| &s.log_records)
            .collect();
        let bodies: Vec<_> = records
            .iter()
            .filter_map(|r| match r.body.as_ref()?.value.as_ref()? {
                any_value::Value::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            bodies,
            ["a credential was added"],
            "only the event the filter lets through"
        );
        assert_eq!(
            string(&records[0].attributes, "vault").as_deref(),
            Some("ops")
        );

        let metrics: Vec<_> = received
            .iter()
            .filter(|(path, _)| path == "/v1/metrics")
            .flat_map(|(_, body)| {
                ExportMetricsServiceRequest::decode(body.clone())
                    .unwrap()
                    .resource_metrics
            })
            .collect();
        let resource = metrics[0].resource.as_ref().unwrap();
        assert_eq!(
            string(&resource.attributes, "team").as_deref(),
            Some("platform")
        );
        let injected = metrics
            .iter()
            .flat_map(|r| &r.scope_metrics)
            .flat_map(|s| &s.metrics)
            .find(|m| m.name == "tokenless.proxy.requests_injected")
            .expect("the injected-requests counter is sent");
        let Some(metric::Data::Sum(sum)) = &injected.data else {
            panic!("a counter is a sum: {:?}", injected.data);
        };
        assert!(sum.is_monotonic);
        assert_eq!(
            sum.data_points[0].value,
            Some(number_data_point::Value::AsInt(3))
        );
        telemetry.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_collector_costs_a_bounded_wait_at_shutdown() {
        // Nothing listens on port 1.
        let settings = Settings {
            endpoint: Some("http://127.0.0.1:1".into()),
            logs_timeout: Duration::from_millis(300),
            metrics_timeout: Duration::from_millis(300),
            ..Settings::from_env(env(&[(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "http://127.0.0.1:1",
            )]))
        };
        let telemetry = Telemetry::start(&settings, Component::Proxy { node_id: None }).unwrap();
        let subscriber =
            tracing_subscriber::registry().with(telemetry.log_layer(EnvFilter::new("info")));
        tracing::subscriber::with_default(subscriber, || tracing::info!("never delivered"));
        telemetry.watch_proxy(Arc::new(Metrics::default()));
        let started = std::time::Instant::now();
        telemetry.shutdown().await;
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "shutdown took {:?}",
            started.elapsed()
        );
    }
}
