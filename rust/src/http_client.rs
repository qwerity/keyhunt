//! HTTP client for coordinator: get_number, mark_done, set_found, status.

use crate::config::ServerConfig;
use crate::Error;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

pub struct HttpClient {
    base_url: String,
    auth_header: String,
    machine_id: String,
    client: Client,
}

impl HttpClient {
    pub fn new(config: &ServerConfig, connect_timeout_sec: Option<u64>, read_write_timeout_sec: Option<u64>) -> Self {
        let port = if config.port.is_empty() { "80" } else { config.port.as_str() };
        let base_url = format!("http://{}:{}", config.url, port);
        let timeout = read_write_timeout_sec.unwrap_or(45);
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(connect_timeout_sec.unwrap_or(60)))
            .timeout(Duration::from_secs(timeout))
            .build()
            .expect("reqwest client");
        let machine_id = config.machine_id.as_deref().unwrap_or("").to_string();
        HttpClient {
            base_url,
            auth_header: config.authorisation_header.clone(),
            machine_id,
            client,
        }
    }

    fn auth_request(&self, req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        let r = req.header("Authorization", &self.auth_header);
        if self.machine_id.is_empty() {
            r
        } else {
            r.header("X-Machine-Id", &self.machine_id)
        }
    }

    pub fn host_config(&self) -> String {
        let mask = if self.auth_header.len() > 4 {
            format!("{}****", "*".repeat(self.auth_header.len().saturating_sub(4)))
        } else {
            "****".into()
        };
        format!("{} | {}", self.base_url, mask)
    }

    /// GET /status
    pub fn host_alive(&self) -> bool {
        let url = format!("{}/status", self.base_url);
        let res = self.auth_request(self.client.get(&url)).send();
        match res {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }

    /// GET /get_number?count=1 -> {"numbers": [N]}
    pub fn get_x_part_number(&self) -> Result<u32, Error> {
        let mut v = self.get_x_part_numbers(1)?;
        v.pop().ok_or_else(|| Error::Http("get_number: empty".into()))
    }

    /// GET /get_number?count=N -> {"numbers": [n1, n2, ...]}
    pub fn get_x_part_numbers(&self, count: usize) -> Result<Vec<u32>, Error> {
        let count = count.max(1);
        let url = format!("{}/get_number?count={}", self.base_url, count);
        let res = self.auth_request(self.client.get(&url)).send()
            .map_err(|e| Error::Http(e.to_string()))?;
        if !res.status().is_success() {
            return Err(Error::Http(format!("get_number status {}", res.status())));
        }
        let json: Value = res.json().map_err(|e| Error::Http(e.to_string()))?;
        let arr = json.get("numbers")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Http("get_number: no 'numbers' array".into()))?;
        let out: Vec<u32> = arr
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u32))
            .collect();
        Ok(out)
    }

    /// POST /mark_done body {"nums": [N]}
    pub fn mark_x_part_done(&self, number: u32) -> bool {
        self.mark_x_part_done_batch(&[number])
    }

    pub fn mark_x_part_done_batch(&self, numbers: &[u32]) -> bool {
        if numbers.is_empty() {
            return true;
        }
        let body = serde_json::json!({ "nums": numbers });
        let url = format!("{}/mark_done", self.base_url);
        let res = self.auth_request(self.client.post(&url))
            .header("Content-Type", "application/json")
            .json(&body)
            .send();
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                log::error!("mark_done HTTP request failed (batch size {}): {}", numbers.len(), e);
                return false;
            }
        };
        if res.status() == StatusCode::ACCEPTED || res.status() == StatusCode::REQUEST_TIMEOUT {
            return true;
        }
        if !res.status().is_success() {
            log::error!("mark_done returned status {} (batch size {})", res.status(), numbers.len());
            return false;
        }
        let json: Value = match res.json() {
            Ok(j) => j,
            Err(e) => {
                log::error!("mark_done response parse failed (batch size {}): {}", numbers.len(), e);
                return false;
            }
        };
        let ok = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            log::error!("mark_done server returned success=false (batch size {})", numbers.len());
        }
        ok
    }

    /// POST /overfitted body {"x": N, "y": M}
    pub fn set_x_part_found(&self, x: u32, y: u32) -> bool {
        let body = serde_json::json!({ "x": x, "y": y });
        let url = format!("{}/overfitted", self.base_url);
        let res = self.auth_request(self.client.post(&url))
            .header("Content-Type", "application/json")
            .json(&body)
            .send();
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                log::error!("overfitted HTTP request failed");
                return false;
            }
        };
        if res.status() != StatusCode::OK {
            log::error!("overfitted returned status {}", res.status());
            return false;
        }
        let json: Value = match res.json() {
            Ok(j) => j,
            Err(e) => {
                log::error!("overfitted response parse failed");
                return false;
            }
        };
        let ok = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            log::error!("overfitted server returned success=false");
        }
        ok
    }
}
