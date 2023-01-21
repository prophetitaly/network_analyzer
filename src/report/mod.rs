use std::collections::HashMap;
use std::{fmt, mem};
use std::fmt::{Display};
use prettytable::{row, Table};
use crate::packet::Packet;

#[derive(Default, Debug, Clone)]
pub struct Report {
    // pub report_lines: HashMap<String, HashMap<String, ReportLine>>
    pub report_lines: HashMap<(String, String), ReportLine>,
}

#[derive(Default, Debug, Clone)]
pub struct ReportLine {
    pub timestamp_first: String,
    pub timestamp_last: String,
    pub source_optional_port: String,
    pub destination_optional_port: String,
    pub protocols: Vec<String>,
    pub bytes_total: u32,
}

impl Report {
    pub fn new() -> Self {
        Report {
            report_lines: HashMap::new(),
        }
    }
    pub fn get_report_lines(&mut self) -> &mut HashMap<(String, String), ReportLine> {
        &mut self.report_lines
    }
    pub fn add_packet(&mut self, packet: Packet) {
        let mut addr1 = packet.get_source().clone() +
            &(match packet.get_source_port() {
                Some(port) => (":".to_owned() + port).to_owned(),
                None => "".to_owned(),
            });
        let mut addr2 = packet.get_destination().clone() +
            &(match packet.get_destination_port() {
                Some(port) => (":".to_owned() + port).to_owned(),
                None => "".to_owned(),
            });
        if addr1 > addr2 {
            mem::swap(&mut addr1, &mut addr2);
        }
        let key = (addr1, addr2).clone();
        let mut report_lines = self.get_report_lines();

        if report_lines.get_mut(&key).is_none() {
            let mut rl = ReportLine::default();
            rl.set_timestamp_first(packet.get_timestamp().clone());
            rl.set_timestamp_last(packet.get_timestamp().clone());
            rl.set_source_optional_port(packet.get_source().clone() +
                &*match packet.get_source_port() {
                    Some(port) => ":".to_owned() + port,
                    None => "".to_owned(),
                });
            rl.set_destination_optional_port(packet.get_destination().clone() +
                &*match packet.get_destination_port() {
                    Some(port) => ":".to_owned() + port,
                    None => "".to_owned(),
                });
            rl.add_protocol(packet.get_protocol().clone());
            rl.set_bytes_total(packet.get_length().clone());
            report_lines.insert(key, rl);
        } else {
            report_lines.get_mut(&key).unwrap().add_packet(packet.clone());
        }
    }

    pub fn to_formatted_table(&self) -> Table {
        let mut table = Table::new();
        table.add_row(row!["First Timestamp", "Last Timestamp", "Address 1", "Address 2", "Protocols", "Bytes Total"]);
        for (_, rls) in self.report_lines.iter() {
            table.add_row(row![rls.timestamp_first, rls.timestamp_last, rls.source_optional_port, rls.destination_optional_port, rls.protocols.join(","), rls.bytes_total]);
        }
        table
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.report_lines.iter().fold(Ok(()), |result, rls| {
            result.and_then(|_| writeln!(f, "{}", rls.1))
        })
    }
}

impl ReportLine {
    pub fn new() -> Self {
        ReportLine {
            timestamp_first: String::new(),
            timestamp_last: String::new(),
            source_optional_port: String::new(),
            destination_optional_port: String::new(),
            protocols: Vec::new(),
            bytes_total: 0,
        }
    }
    pub fn set_timestamp_first(&mut self, timestamp_first: String) {
        self.timestamp_first = timestamp_first;
    }
    pub fn set_timestamp_last(&mut self, timestamp_last: String) {
        self.timestamp_last = timestamp_last;
    }
    pub fn set_source_optional_port(&mut self, source_optional_port: String) {
        self.source_optional_port = source_optional_port;
    }
    pub fn set_destination_optional_port(&mut self, destination_optional_port: String) {
        self.destination_optional_port = destination_optional_port;
    }
    pub fn add_protocol(&mut self, protocol: String) {
        self.protocols.push(protocol);
    }
    pub fn set_bytes_total(&mut self, bytes_total: u32) {
        self.bytes_total = bytes_total;
    }
    pub fn add_packet(&mut self, packet: Packet) {
        if !self.protocols.contains(packet.get_protocol()) {
            self.protocols.push(packet.get_protocol().clone());
        }
        self.bytes_total += packet.get_length();
        if self.timestamp_last < *packet.get_timestamp() {
            self.timestamp_last = packet.get_timestamp().clone();
        } else if self.timestamp_first > *packet.get_timestamp() {
            self.timestamp_first = packet.get_timestamp().clone();
        }
    }
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        s.push_str(&self.timestamp_first);
        s.push_str(" ");
        s.push_str(&self.timestamp_last);
        s.push_str(" ");
        s.push_str(&self.source_optional_port);
        s.push_str(" ");
        s.push_str(&self.destination_optional_port);
        s.push_str(" ");
        for protocol in self.protocols.iter() {
            s.push_str(protocol);
            s.push_str(", ");
        }
        s.push_str(&self.bytes_total.to_string());
        s
    }
}

impl Display for ReportLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {}", self.timestamp_first, self.timestamp_last, self.source_optional_port, self.destination_optional_port, self.protocols.join(","), self.bytes_total)
    }
}