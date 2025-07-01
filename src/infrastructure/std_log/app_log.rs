use actix_web::HttpResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;

/// Represents the types of logs that can be recorded or serialized in the system.
///
/// Each variant corresponds to a specific log type, with associated `serde` renaming
/// for compatibility during serialization and deserialization processes.
///
/// # Variants
///
/// - `AppLog`:
///   This corresponds to application-level logs used to record general application activities or events.
///   Serialized as `"APP_LOG"`.
///
/// - `ReqLog`:
///   Represents logs related to requests. These logs generally capture the incoming request data.
///   Serialized as `"REQ_LOG"`.
///
/// - `ReqExLog`:
///   Denotes logs for exceptions or additional context during the request phase.
///   Serialized as `"REQ_EX_LOG"`.
///
/// - `ResLog`:
///   Refers to logs pertaining to responses. These logs typically document the outgoing response data.
///   Serialized as `"RES_LOG"`.
///
/// - `ResExLog`:
///   Indicates logs for exceptions or additional context during the response phase.
///   Serialized as `"RES_EX_LOG"`.
///
/// - `PIILog`:
///   Represents logs containing Personally Identifiable Information (PII). Handle these with care
///   as they may contain sensitive data. Serialized as `"PII_LOG"`.
///
/// # Derives
///
/// - `Debug`: Allows debug prints of the `LogType` values.
/// - `Clone`: Enables cloning of `LogType` instances.
/// - `Serialize` and `Deserialize`: Supports serialization and deserialization using `serde`.
/// - `PartialEq`: Allows comparison between `LogType` instances.
///
/// # Usage Example
///
/// ```rust
/// use serde_json;
/// use your_crate::LogType;
///
/// let log_type = LogType::ReqLog;
/// let serialized = serde_json::to_string(&log_type).unwrap();
/// assert_eq!(serialized, "\"REQ_LOG\"");
///
/// let deserialized: LogType = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, LogType::ReqLog);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogType {
    #[serde(rename = "APP_LOG")]
    AppLog,
    #[serde(rename = "REQ_LOG")]
    ReqLog,
    #[serde(rename = "REQ_EX_LOG")]
    ReqExLog,
    #[serde(rename = "RES_LOG")]
    ResLog,
    #[serde(rename = "RES_EX_LOG")]
    ResExLog,
    #[serde(rename = "PII_LOG")]
    PIILog,
}
/// Represents logging levels used for categorizing log messages.
///
/// This enum provides different levels of logging severity. It can be serialized
/// and deserialized (e.g., for configuration purposes) and also implements traits
/// for debugging, cloning, and comparison.
///
/// # Variants
///
/// * `Debug`: Denotes detailed debugging information. Serialized as `"debug"`.
/// * `Info`: Represents informational messages that highlight the progress
///   of the application. Serialized as `"info"`.
/// * `Warn`: Indicates potentially harmful situations. Serialized as `"warn"`.
/// * `Error`: Defines error-level messages that signify a failure. Serialized as `"error"`.
///
/// # Traits
///
/// This enum derives the following traits:
/// * `Debug`: Enables formatting using the `{:?}` formatter.
/// * `Clone`: Allows creating a duplicate of a `LogLevel` value.
/// * `Serialize` and `Deserialize`: Allows conversion to and from data formats (e.g., JSON).
/// * `PartialEq`: Enables equality comparisons between values of `LogLevel`.
///
/// # Example
///
/// ```
/// use your_crate::LogLevel;
///
/// let level = LogLevel::Info;
///
/// // Serialize to JSON
/// let serialized = serde_json::to_string(&level).unwrap();
/// assert_eq!(serialized, "\"info\"");
///
/// // Deserialize from JSON
/// let deserialized: LogLevel = serde_json::from_str("\"warn\"").unwrap();
/// assert_eq!(deserialized, LogLevel::Warn);
///
/// println!("LogLevel variant: {:?}", deserialized);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "error")]
    Error,
}

fn serialize_datetime_iso8601<S>(datetime: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Format: 2025-01-18T14:53:03.123Z
    let s = datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    serializer.serialize_str(&s)
}
/// Represents an application log entry with various metadata fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SCBLog {
    /// [M][A] Event date and time in ISO 8601 format (e.g., "2025-01-18T14:53:03.123Z").\
    #[serde(serialize_with = "serialize_datetime_iso8601")]
    pub event_date_time: DateTime<Utc>,

    /// [M][D] Type of log: "APP_LOG", "REQ_LOG", "REQ_EX_LOG", or "RES_LOG".
    pub log_type: LogType,

    /// [O][A] Application ID assigned by SCB IT (e.g., "AP1234").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,

    /// [O][A] Application release version (e.g., "1.0.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,

    /// [O][A] Application address (e.g., "192.168.1.1:8080").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_address: Option<String>,

    /// [O][A] Geographical location or data center (e.g., "az-southeastasia").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_location: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// [M][A] Service ID or name (e.g., "Auth-service").
    pub service_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// [M][A] Microservice version or image tag (e.g., "v1.2.3").
    pub service_version: Option<String>,

    /// [O][A] Pod name if the application is running on Kubernetes (e.g., "portal-ui-xyz").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_pod_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// [M][D] Code location such as module or function name (e.g., "com.report.reportManager.getReport").
    pub code_location: Option<String>,

    /// [O][D] Name or code of the caller channel (e.g., "STEL").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_channel_name: Option<String>,

    /// [O][D] User ID or name of the caller (e.g., "John Doe").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_user: Option<String>,

    /// [O][D] Address of the caller (e.g., "237.84.2.178").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// [M][D] Correlation ID for end-to-end request tracking.
    pub correlation_id: Option<String>,

    /// [O][D] Unique request ID per HTTP request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,

    /// [M][O] Log severity level: "DEBUG", "INFO", "WARN", or "ERROR".
    pub level: LogLevel,

    /// [O][D] Execution time in milliseconds (e.g., 300).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_time: Option<u32>,

    /// [M][D] Log message detailing the action or event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_log: Option<PIILog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIILogUpdate {
    pub previous_values: HashMap<String, String>,
    pub new_values: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_values: Option<HashMap<String, String>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIILog {
    pub event_type: String, // เช่น "PII_UPDATE"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_criteria: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<PIILogUpdate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_values: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_key_values: Option<HashMap<String, String>>,
}

pub struct PIILogBuilder {
    event_type: String,
    search_criteria: Option<HashMap<String, String>>,
    update: Option<PIILogUpdate>,
    new_values: Option<HashMap<String, String>>,
    delete_key_values: Option<HashMap<String, String>>,
}

impl PIILogBuilder {
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            search_criteria: None,
            update: None,
            new_values: None,
            delete_key_values: None,
        }
    }

    pub fn search_criteria(mut self, key: &str, value: &str) -> Self {
        self.search_criteria
            .get_or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn add_update_previous(mut self, key: &str, value: &str) -> Self {
        if self.update.is_none() {
            self.update = Some(PIILogUpdate {
                previous_values: HashMap::new(),
                new_values: HashMap::new(),
                key_values: None,
            });
        }
        self.update
            .as_mut()
            .unwrap()
            .previous_values
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn add_update_new(mut self, key: &str, value: &str) -> Self {
        if self.update.is_none() {
            self.update = Some(PIILogUpdate {
                previous_values: HashMap::new(),
                new_values: HashMap::new(),
                key_values: None,
            });
        }
        self.update
            .as_mut()
            .unwrap()
            .new_values
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn add_update_key(mut self, key: &str, value: &str) -> Self {
        if self.update.is_none() {
            self.update = Some(PIILogUpdate {
                previous_values: HashMap::new(),
                new_values: HashMap::new(),
                key_values: Some(HashMap::new()),
            });
        } else if self.update.as_ref().unwrap().key_values.is_none() {
            self.update.as_mut().unwrap().key_values = Some(HashMap::new());
        }

        self.update
            .as_mut()
            .unwrap()
            .key_values
            .as_mut()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn add_new_value(mut self, key: &str, value: &str) -> Self {
        self.new_values
            .get_or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn add_delete_key(mut self, key: &str, value: &str) -> Self {
        self.delete_key_values
            .get_or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> PIILog {
        PIILog {
            event_type: self.event_type,
            search_criteria: self.search_criteria,
            update: self.update,
            new_values: self.new_values,
            delete_key_values: self.delete_key_values,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub url: String,
    pub method: String,
    pub body: Value,
}

impl Request {
    pub fn from_actix(req: &actix_web::HttpRequest, body: Value) -> Self {
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        Request {
            id: uuid::Uuid::new_v4().to_string(), // หรือดึงจาก header
            host: "localhost".to_string(),
            headers,
            url: req.uri().to_string(),
            method: req.method().to_string(),
            body,
        }
    }
}

pub struct RequestBuilder {
    id: String,
    host: String, // อาจจะใช้ในอนาคต
    headers: HashMap<String, String>,
    url: String,
    method: String,
    body: Value,
}

impl RequestBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            headers: HashMap::new(),
            host: String::new(), // อาจจะใช้ในอนาคต
            url: String::new(),
            method: String::from("GET"),
            body: Value::Null,
        }
    }
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn body(mut self, body: Value) -> Self {
        self.body = body;
        self
    }

    pub fn build(self) -> Request {
        Request {
            id: self.id,
            host: self.host,
            headers: self.headers,
            url: self.url,
            method: self.method,
            body: self.body,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status_code: u32,
    pub headers: HashMap<String, String>,
    pub body: Value,
}

impl Response {
    pub async fn from_actix(resp: &HttpResponse) -> Self {
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect::<HashMap<String, String>>();

        // ถ้า response body ไม่ได้ log ได้ตรงๆ ให้ใส่ Value::Null หรือ dummy
        // หรือแปลง body เป็น String ถ้าได้
        Response {
            status_code: resp.status().as_u16() as u32,
            headers,
            body: Value::Null, // อาจเปลี่ยนเป็น Text หรือ JSON ถ้าสามารถอ่าน body ได้
        }
    }
}

pub struct ResponseBuilder {
    status_code: u32,
    headers: HashMap<String, String>,
    body: Value,
}

impl ResponseBuilder {
    pub fn new(status_code: u32) -> Self {
        Self {
            status_code,
            headers: HashMap::new(),
            body: Value::Null,
        }
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn body(mut self, body: Value) -> Self {
        self.body = body;
        self
    }

    pub fn build(self) -> Response {
        Response {
            status_code: self.status_code,
            headers: self.headers,
            body: self.body,
        }
    }
}

pub struct SCBLogBuilder {
    log: SCBLog,
}

impl SCBLogBuilder {
    pub fn new(log_type: LogType) -> Self {
        SCBLogBuilder {
            log: SCBLog {
                event_date_time: Utc::now(),
                log_type,
                app_id: None,
                app_version: None,
                app_address: None,
                geo_location: None,
                service_id: None,
                service_version: None,
                service_pod_name: None,
                code_location: None,
                caller_channel_name: None,
                caller_user: None,
                caller_address: None,
                correlation_id: None,
                request_id: None,
                trace_id: None,
                span_id: None,
                level: LogLevel::Info,
                execution_time: None,
                message: None,
                request: None,
                response: None,
                pii_log: None,
            },
        }
    }

    pub fn from_base(base: &SCBLog, log_type: LogType) -> Self {
        SCBLogBuilder {
            log: SCBLog {
                event_date_time: Utc::now(),
                log_type,
                app_id: base.app_id.clone(),
                app_version: base.app_version.clone(),
                app_address: base.app_address.clone(),
                geo_location: base.geo_location.clone(),
                service_id: base.service_id.clone(),
                service_version: base.service_version.clone(),
                service_pod_name: base.service_pod_name.clone(),
                code_location: Some(String::new()), // ต้อง override
                caller_channel_name: base.caller_channel_name.clone(),
                caller_user: None,
                caller_address: None,
                correlation_id: Some(String::new()), // ต้อง override
                request_id: None,
                trace_id: None,
                span_id: None,
                level: LogLevel::Info, // default
                execution_time: None,
                message: Some(String::new()), // ต้อง override
                request: None,
                response: None,
                pii_log: None,
            },
        }
    }

    #[warn(dead_code)]
    pub fn event_date_time(mut self, dt: DateTime<Utc>) -> Self {
        self.log.event_date_time = dt;
        self
    }
    pub fn log_type(mut self, log_type: LogType) -> Self {
        self.log.log_type = log_type;
        self
    }
    pub fn app_id(mut self, id: impl Into<String>) -> Self {
        self.log.app_id = Some(id.into());
        self
    }

    pub fn app_version(mut self, version: impl Into<String>) -> Self {
        self.log.app_version = Some(version.into());
        self
    }

    pub fn app_address(mut self, addr: impl Into<String>) -> Self {
        self.log.app_address = Some(addr.into());
        self
    }

    pub fn geo_location(mut self, location: impl Into<String>) -> Self {
        self.log.geo_location = Some(location.into());
        self
    }

    pub fn service_id(mut self, id: impl Into<String>) -> Self {
        self.log.service_id = Some(id.into());
        self
    }

    pub fn service_version(mut self, version: impl Into<String>) -> Self {
        self.log.service_version = Some(version.into());
        self
    }

    pub fn service_pod_name(mut self, name: impl Into<String>) -> Self {
        self.log.service_pod_name = Some(name.into());
        self
    }

    pub fn code_location(mut self, location: impl Into<String>) -> Self {
        self.log.code_location = Some(location.into());
        self
    }

    pub fn caller_channel_name(mut self, name: impl Into<String>) -> Self {
        self.log.caller_channel_name = Some(name.into());
        self
    }
    pub fn caller_user(mut self, user: impl Into<String>) -> Self {
        self.log.caller_user = Some(user.into());
        self
    }
    pub fn caller_address(mut self, addr: impl Into<String>) -> Self {
        self.log.caller_address = Some(addr.into());
        self
    }

    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.log.correlation_id = Some(id.into());
        self
    }

    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.log.request_id = Some(id.into());
        self
    }
    
    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.log.trace_id = Some(id.into());
        self
    }
    pub fn span_id(mut self, id: impl Into<String>) -> Self {
        self.log.span_id = Some(id.into());
        self
    }

    pub fn level(mut self, level: LogLevel) -> Self {
        self.log.level = level;
        self
    }

    pub fn execution_time(mut self, time_ms: u32) -> Self {
        self.log.execution_time = Some(time_ms);
        self
    }

    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.log.message = Some(msg.into());
        self
    }

    pub fn request(mut self, req: Request) -> Self {
        self.log.request = Some(req);
        self
    }

    pub fn response(mut self, res: Response) -> Self {
        self.log.response = Some(res);
        self
    }

    pub fn pii_log(mut self, pii: PIILog) -> Self {
        self.log.pii_log = Some(pii);
        self
    }

    pub fn build(mut self) -> SCBLog {
        self.log.event_date_time = Utc::now();
        self.log
    }
}
