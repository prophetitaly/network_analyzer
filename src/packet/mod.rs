use std::fmt;
use chrono::{DateTime, NaiveDateTime, Utc};
use libc::{c_long};
use num_traits::FromPrimitive;

#[derive(Debug, Clone, PartialEq)]
/// Represents a packet captured by the library
pub struct Packet {
    /// The time when the packet was captured
    timestamp: String,
    /// The source IP address
    source: String,
    /// The destination IP address
    destination: String,
    /// The source port
    source_port: Option<String>,
    /// The destination port
    destination_port: Option<String>,
    /// The protocol used by the packet
    protocol: String,
    /// The length of the packet
    length: u32,
    /// Some additional info that can be registered
    info: String,
}

impl Packet {
    pub fn new(timestamp: String, source: String, destination: String, source_port: Option<String>, destination_port: Option<String>, protocol: String, length: u32, info: String) -> Self {
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
        let ts;
        let ts_ns;
        if cfg!(target_os = "linux") {
            ts = i64::from_i64(*timestamp as i64).unwrap();
            ts_ns = u32::from_i64(*timestamp_ns as i64).unwrap();
        } else {
            ts = i64::from_i32(*timestamp).unwrap();
            ts_ns = u32::from_i32(*timestamp_ns).unwrap();
        }
        // Create a NaiveDateTime from the timestamp
        let naive = NaiveDateTime::from_timestamp_opt(ts, ts_ns*1000).unwrap();

        // Create a normal DateTime from the NaiveDateTime and then turn it into a Local DateTime
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        let datetime_local = datetime.with_timezone(&chrono::Local);

        // Format the datetime how you want
        let newdate = datetime_local.format("%H:%M:%S%.3f");
        self.timestamp = newdate.to_string();
    }

    //Setters
    pub fn set_source(&mut self, source: String) {
        self.source = source;
    }
    pub fn set_destination(&mut self, destination: String) {
        self.destination = destination;
    }
    pub fn set_source_port(&mut self, source_port: Option<String>) {
        self.source_port = source_port;
    }
    pub fn set_destination_port(&mut self, destination_port: Option<String>) {
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

    //Getters
    pub fn get_timestamp(&self) -> &String {
        &self.timestamp
    }
    pub fn get_source(&self) -> &String {
        &self.source
    }
    pub fn get_destination(&self) -> &String {
        &self.destination
    }
    pub fn get_source_port(&self) -> &Option<String> {
        &self.source_port
    }
    pub fn get_destination_port(&self) -> &Option<String> {
        &self.destination_port
    }
    pub fn get_protocol(&self) -> &String {
        &self.protocol
    }
    pub fn get_length(&self) -> &u32 {
        &self.length
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {} {}",
               self.timestamp,
               self.source,
               self.destination,
               match self.source_port {
                   Some(ref port) => port,
                   None => "",
               },
               match self.destination_port {
                     Some(ref port) => port,
                     None => "",
               },
               self.protocol,
               self.length,
               self.info)
    }
}