use std::collections::HashMap;
use std::{fmt, mem};
use std::borrow::BorrowMut;
use std::fmt::{Display};
use crate::packet::Packet;

#[derive(Default, Debug, Clone)]
pub struct Report {
    pub report_lines: HashMap<String, HashMap<String, ReportLine>>,
    //TODO: vede quale versione è meglio
    //pub report_lines_v2: HashMap<(String, String),ReportLine>,
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
    pub fn get_report_lines(&mut self) -> &mut HashMap<String, HashMap<String, ReportLine>> {
        &mut self.report_lines
    }
    pub fn add_packet(&mut self, packet: Packet) {
        let mut addr1 = packet.get_source().clone() + ":" + packet.get_source_port();
        let mut addr2 = packet.get_destination().clone() + ":" + packet.get_destination_port();
        if addr1 > addr2 {
            mem::swap(&mut addr1, &mut addr2);
        }
        let mut report_lines = self.get_report_lines();

        if report_lines.get(&addr1).is_none() {
            report_lines.insert(addr1.clone(), HashMap::new());
        }

        let report_line_collection = report_lines.get_mut(&addr1).unwrap();

        if report_line_collection.get(&addr2).is_none() {
            let mut rl = ReportLine::default();
            rl.set_timestamp_first(packet.get_timestamp().clone());
            rl.set_timestamp_last(packet.get_timestamp().clone());
            rl.set_source_optional_port(packet.get_source().clone() + ":" + packet.get_source_port());
            rl.set_destination_optional_port(packet.get_destination().clone() + ":" + packet.get_destination_port());
            rl.add_protocol(packet.get_protocol().clone());
            rl.set_bytes_total(packet.get_length().clone());
            report_line_collection.insert(addr2, rl);
        } else {
            report_line_collection.get_mut(&addr2).unwrap().add_packet(packet.clone());
        }

        // //TODO: optimize this Uso una hashmap o simile. Ordino gli indirizzi per minore e maggiore come destination e source. Indirizzo = chiave hashmap.
        // for mut rl in report_lines{
        //     if rl.source_optional_port.eq(&*(addr1)) && rl.destination_optional_port.eq(&*(addr2)){
        //         rl.add_packet(packet.clone());
        //     } else if rl.destination_optional_port.eq(&*(addr1)) && rl.source_optional_port.eq(&*(addr2)){
        //         rl.add_packet(packet.clone());
        //     } else {
        //         let mut report_line = ReportLine::default();
        //         report_line.set_timestamp_first(packet.get_timestamp().clone());
        //         report_line.set_timestamp_last(packet.get_timestamp().clone());
        //         report_line.set_source_optional_port(packet.get_source().clone() + ":" + packet.get_source_port());
        //         report_line.set_destination_optional_port(packet.get_destination().clone() + ":" + packet.get_destination_port());
        //         report_line.add_protocol(packet.get_protocol().clone());
        //         report_line.set_bytes_total(packet.get_length().clone());
        //         self.add_report_line(report_line);
        //     }
        // }
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.report_lines.iter().fold(Ok(()), |result, rls| {
            rls.1.iter().fold(Ok(()), |result, rl| {
                result.and_then(|_| writeln!(f, "{}", rl.1))
            })
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
        } else if self.timestamp_first < *packet.get_timestamp() {
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