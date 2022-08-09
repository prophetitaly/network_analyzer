use std::fmt;
use std::fmt::{Display};
use crate::packet::Packet;

#[derive(Default, Debug, Clone)]
pub struct Report {
    pub report_lines: Vec<ReportLine>,
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
            report_lines: Vec::new(),
        }
    }
    pub fn add_report_line(&mut self, report_line: ReportLine) {
        self.report_lines.push(report_line);
    }
    pub fn get_report_lines(&self) -> &Vec<ReportLine> {
        &self.report_lines
    }
    pub fn add_packet(&mut self, packet: Packet) {
        let addr1 = packet.get_source().clone() + ":" + packet.get_source_port();
        let addr2 = packet.get_destination().clone() + ":" + packet.get_destination_port();
        let report_lines = self.get_report_lines().clone();

        if report_lines.is_empty() {
            let mut report_line = ReportLine::default();
            report_line.set_timestamp_first(packet.get_timestamp().clone());
            report_line.set_timestamp_last(packet.get_timestamp().clone());
            report_line.set_source_optional_port(packet.get_source().clone() + ":" + packet.get_source_port());
            report_line.set_destination_optional_port(packet.get_destination().clone() + ":" + packet.get_destination_port());
            report_line.add_protocol(packet.get_protocol().clone());
            report_line.set_bytes_total(packet.get_length().clone());
            self.add_report_line(report_line);
        }

        //TODO: optimize this Uso una hashmap o simile. Ordino gli indirizzi per minore e maggiore come destination e source. Indirizzo = chiave hashmap.
        for mut rl in report_lines{
            if rl.source_optional_port.eq(&*(addr1)) && rl.destination_optional_port.eq(&*(addr2)){
                rl.add_packet(packet.clone());
            } else if rl.destination_optional_port.eq(&*(addr1)) && rl.source_optional_port.eq(&*(addr2)){
                rl.add_packet(packet.clone());
            } else {
                let mut report_line = ReportLine::default();
                report_line.set_timestamp_first(packet.get_timestamp().clone());
                report_line.set_timestamp_last(packet.get_timestamp().clone());
                report_line.set_source_optional_port(packet.get_source().clone() + ":" + packet.get_source_port());
                report_line.set_destination_optional_port(packet.get_destination().clone() + ":" + packet.get_destination_port());
                report_line.add_protocol(packet.get_protocol().clone());
                report_line.set_bytes_total(packet.get_length().clone());
                self.add_report_line(report_line);
            }
        }
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.report_lines.iter().fold(Ok(()), |result, rl| {
            result.and_then(|_| writeln!(f, "{}", rl))
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
        } else if self.timestamp_first < *packet.get_timestamp(){
            self.timestamp_first = packet.get_timestamp().clone();
        }
    }
}

impl Display for ReportLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {}", self.timestamp_first, self.timestamp_last, self.source_optional_port, self.destination_optional_port, self.protocols.join(","), self.bytes_total)
    }
}