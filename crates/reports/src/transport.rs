










use std::io::Read;
use std::time::Duration;

pub const USER_AGENT: &str = concat!("BinScope/", env!("CARGO_PKG_VERSION"));





const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self {
            method: Method::Post,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn form(self, fields: &[(&str, &str)]) -> Self {
        let body = fields
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        self.header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
    }

    pub fn json(self, value: &serde_json::Value) -> Self {
        self.header("Content-Type", "application/json")
            .body(value.to_string())
    }
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub retry_after_secs: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Connect,
    Other,
}



pub trait Transport: Send + Sync {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}



pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
    timeout: Duration,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            

            

            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|error| format!("could not create the HTTP client: {error}"))?;
        Ok(Self {
            client,
            timeout: Duration::from_secs(20),
        })
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        if !request.url.starts_with("https://") {
            return Err(TransportError::Other);
        }
        let mut builder = match request.method {
            Method::Get => self.client.get(&request.url),
            Method::Post => self.client.post(&request.url),
        };
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }
        let response = builder.send().map_err(|error| {
            if error.is_timeout() {
                TransportError::Timeout
            } else if error.is_connect() {
                TransportError::Connect
            } else {
                TransportError::Other
            }
        })?;

        let status = response.status().as_u16();
        let retry_after_secs = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        let mut body = String::new();
        response
            .take(MAX_RESPONSE_BYTES)
            .read_to_string(&mut body)
            .map_err(|_| TransportError::Other)?;
        Ok(HttpResponse {
            status,
            body,
            retry_after_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding_keeps_the_hash_intact() {
        let request = HttpRequest::post("https://example.invalid/api")
            .form(&[("query", "get_info"), ("hash", "ab12")]);
        assert_eq!(request.body.as_deref(), Some("query=get_info&hash=ab12"));
        assert!(request
            .headers
            .iter()
            .any(|(name, _)| name == "Content-Type"));
    }

    #[test]
    fn form_encoding_escapes_separators_and_unicode() {
        let request = HttpRequest::get("https://example.invalid").form(&[
            ("term", "a&b=c"),
            ("name", "ñandú"),
        ]);
        let body = request.body.unwrap();
        assert!(body.contains("term=a%26b%3Dc"));
        assert!(body.contains("name=%C3%B1and%C3%BA"));
    }
}
