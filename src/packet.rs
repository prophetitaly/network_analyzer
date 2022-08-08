use std::fmt;
use chrono::{DateTime, NaiveDateTime, Utc};
use libc::{c_long};
use num_traits::FromPrimitive;

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    timestamp: String,
    source: String,
    destination: String,
    source_port: String,
    destination_port: String,
    protocol: String,
    length: u32,
    info: String,
}

impl Packet {
    pub fn new(timestamp: String, source: String, destination: String, source_port: String, destination_port: String, protocol: String, length: u32, info: String) -> Self {
        Packet {
            timestamp,
            source,
            destination,
            source_port,
            destination_port,
            protocol,
            length,
            info,
        }
    }

    pub fn set_timestamp(&mut self, timestamp: &c_long, timestamp_ns: &c_long) {
        let ts = i64::from_i32(*timestamp).unwrap();
        let ts_ns = u32::from_i32(*timestamp_ns).unwrap();
        // Create a NaiveDateTime from the timestamp
        let naive = NaiveDateTime::from_timestamp(ts, ts_ns*1000);

        // Create a normal DateTime from the NaiveDateTime
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);

        // Format the datetime how you want
        let newdate = datetime.format("%H:%M:%S%.3f");
        self.timestamp = newdate.to_string();
    }
    pub fn set_source(&mut self, source: String) {
        self.source = source;
    }
    pub fn set_destination(&mut self, destination: String) {
        self.destination = destination;
    }
    pub fn set_source_port(&mut self, source_port: String) {
        self.source_port = source_port;
    }
    pub fn set_destination_port(&mut self, destination_port: String) {
        self.destination_port = destination_port;
    }
    pub fn set_protocol(&mut self, protocol: String) {
        self.protocol = protocol;
    }
    pub fn set_length(&mut self, length: &u32) {
        self.length = length.clone();
    }
    pub fn set_info(&mut self, info: String) {
        self.info = info;
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.info)
    }
}