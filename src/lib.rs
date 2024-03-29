//! Simple packet capture and analysis tool
//!
//! # Input
//! The input is a Parameters struct that contains the following information:
//! * device_id: The id of the network device to capture from
//! * timeout: The time after which the capture stops
//! * file_path: The path of the file where the captured packets will be saved
//! * filter: An optional filter to be applied to the captured packets (in BPF format https://biot.com/capstats/bpf.html)
//!
//! # Output
//! The output is written to a file in the following format:
//! Timestamp first | Timestamp last | Address 1 | Address 2 | Protocols | Bytes Total
//!
//! # Usage
//! let control_block = analyze_network(Parameters {
//!                 device_id: 1,
//!                 timeout: 1,
//!                 file_path: output.txt,
//!                 filter: None,
//!             });
mod packet;
pub mod parameters;
mod report;

use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::fs;
use std::fs::{File, metadata};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::{SlicedPacket};
use etherparse::LinkSlice::Ethernet2;
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use pcap::{Device, Capture, PacketHeader, Address, Active};
use threadpool::ThreadPool;
use crate::ConfigError::{InvalidDeviceId, InvalidFilter};
use crate::packet::Packet as MyPacket;
use crate::parameters::Parameters;
use crate::report::Report;

#[derive(Eq, PartialEq, Clone)]
/// There are 3 possible states:
/// 1. The capture is running
/// 2. The capture is paused
/// 3. The capture is stopped
pub enum CaptureState {
    Capturing(),
    Paused(),
    Stopped(),
}

#[derive(Debug)]
pub enum SnifferError {
    ConfigError(ConfigError),
    CaptureError(CaptureError),
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidDeviceId(pcap::Error),
    InvalidTimeout(pcap::Error),
    InvalidFilePath(String),
    InvalidFilter(pcap::Error),
}

#[derive(Debug)]
pub enum CaptureError {
    DeviceError(pcap::Error),
    CaptureError(pcap::Error),
    FilterError(pcap::Error),
}

impl Display for SnifferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SnifferError::ConfigError(e) =>
                write!(f, "Error in configuration: {}", e),
            SnifferError::CaptureError(e) =>
                write!(f, "Error in capture: {}", e),
        }
    }
}

impl std::error::Error for SnifferError {}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidDeviceId(e) =>
                write!(f, "Invalid device id: {}", e),
            ConfigError::InvalidTimeout(e) =>
                write!(f, "Invalid timeout: {}", e),
            ConfigError::InvalidFilePath(e) =>
                write!(f, "Invalid file path: {}", e),
            InvalidFilter(e) =>
                write!(f, "Invalid filter: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Display for CaptureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::DeviceError(e) =>
                write!(f, "Error getting device: {}", e),
            CaptureError::CaptureError(e) =>
                write!(f, "Error capturing packets: {}", e),
            CaptureError::FilterError(e) =>
                write!(f, "Error setting filter: {}", e),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Controls the capture process
pub struct ControlBlock {
    m: Mutex<CaptureState>,
    cv: Condvar,
    timeout: Mutex<u32>,
    output_file: Mutex<String>,
    capture: Mutex<Capture<Active>>,
    error_list: Mutex<VecDeque<SnifferError>>,
}

impl ControlBlock {
    fn new() -> Arc<ControlBlock> {
        Arc::new(ControlBlock {
            m: Mutex::new(CaptureState::Capturing()),
            cv: Condvar::new(),
            timeout: Mutex::new(5),
            output_file: Mutex::new(String::new()),
            capture: Mutex::new(Capture::from_device(Device::lookup().unwrap().unwrap())
                .unwrap()
                .promisc(true)
                .snaplen(5000)
                .timeout(1000)
                .open()
                .unwrap()),
            error_list: Mutex::new(VecDeque::new()),
        })
    }

    /// Gets the current state of the capture.
    ///
    /// There are 2 states:
    /// - Capturing
    /// - Paused
    pub fn get_state(&self) -> CaptureState {
        let state = self.m.lock().unwrap();
        state.clone()
    }

    /// Pauses the capture.
    pub fn pause(&self) {
        let mut state = self.m.lock().unwrap();
        *state = CaptureState::Paused();
        self.cv.notify_all();
    }

    /// Resumes the capture.
    pub fn resume(&self) {
        let mut state = self.m.lock().unwrap();
        *state = CaptureState::Capturing();
        self.cv.notify_all();
    }

    /// Stops the capture.
    pub fn stop(&self) {
        let mut state = self.m.lock().unwrap();
        *state = CaptureState::Stopped();
        self.cv.notify_all();
    }

    fn wait(&self) {
        let mut state = self.m.lock().unwrap();
        while *state == CaptureState::Paused() {
            state = self.cv.wait(state).unwrap();
        }
    }

    /// Gets the timeout of the capture.
    pub fn get_timeout(&self) -> u32 {
        let t = self.timeout.lock().unwrap();
        *t
    }

    /// Sets the timeout for the capture.
    pub fn set_timeout(&self, timeout: u32) {
        let mut t = self.timeout.lock().unwrap();
        *t = timeout;
    }

    /// Gets the output file of the capture.
    pub fn get_output_file(&self) -> String {
        let f = self.output_file.lock().unwrap();
        f.clone()
    }

    /// Sets the output file for the capture.
    pub fn set_output_file(&self, output_file: String) -> Result<(), SnifferError> {
        let mut f = self.output_file.lock().unwrap();
        match metadata(output_file.clone()) {
            Ok(_) => {
                *f = output_file;
                Ok(())
            },
            Err(_) => {
                match File::create(output_file.clone()) {
                    Ok(_) => {
                        *f = output_file;
                        Ok(())
                    },
                    Err(_) => {
                        Err(SnifferError::ConfigError(ConfigError::InvalidFilePath("Invalid file path".to_string())))
                    }
                }
            }
        }
    }

    /// Gets the capture.
    fn get_capture(&self) -> MutexGuard<'_, Capture<Active>> {
        let c = self.capture.lock().unwrap();
        c
    }

    /// Sets the capture.
    fn set_capture(&self, capture: Capture<Active>) {
        let mut c = self.capture.lock().unwrap();
        *c = capture;
    }

    /// Sets the device for the capture. Index starts from 1.
    pub fn set_device(&self, device_id: usize) -> Result<(), SnifferError>{
        let device = match Device::list(){
            Ok(d) => {
                match d.get(device_id - 1) {
                    Some(d) => d.clone(),
                    None => return Err(SnifferError::ConfigError(InvalidDeviceId(pcap::Error::PcapError("Invalid device id".to_string()))))
                }
            },
            Err(e) => return Err(SnifferError::ConfigError(InvalidDeviceId(e)))
        };

        let cap =
            match match Capture::from_device(device){
                Ok(c) => c.promisc(true)
                    .snaplen(5000)
                    .timeout(1000)
                    .open(),
                Err(e) => return Err(SnifferError::ConfigError(InvalidDeviceId(e)))
            } {
                Ok(c) => c,
                Err(e) => return Err(SnifferError::CaptureError(CaptureError::CaptureError(e)))
            };
        self.set_capture(cap);
        Ok(())
    }

    pub fn set_filter(&self, filter: String) -> Result<(), CaptureError> {
        let mut capture = self.get_capture();
        match capture.filter(&filter, true) {
            Ok(_) => {
                self.resume();
                Ok(())
            },
            Err(e) => {
                self.wait();
                Err(CaptureError::FilterError(e))
            },
        }
    }

    pub fn get_errors(&self) -> MutexGuard<'_, VecDeque<SnifferError>> {
        let e = self.error_list.lock().unwrap();
        e
    }

    pub fn clear_errors(&self, size: usize){
        let mut e = self.error_list.lock().unwrap();
        for _ in 0..size {
            e.pop_front();
        }
    }

    pub fn push_error(&self, error: SnifferError) {
        let mut e = self.error_list.lock().unwrap();
        e.push_back(error);
    }
}

/// Gets the list of network interfaces with their addresses.
///
/// ## Example
///
/// Microsoft Interface: [Address { addr: 192.168.56.1, netmask: Some(255.255.255.0), broadcast_addr: Some(255.255.255.255), dst_addr: None }]
pub fn get_devices() -> Result<Vec<(String, Vec<Address>)>, pcap::Error> {
    let devices_list = Device::list();
    if devices_list.is_err() {
        return Err(devices_list.err().unwrap());
    }
    let devices = devices_list.unwrap();
    let mut device_names: Vec<(String, Vec<Address>)> = Vec::new();
    for device in devices {
        if device.desc.is_some() {
            device_names.push((device.desc.unwrap().to_string(), device.addresses));
        } else {
            device_names.push((device.name.to_string(), device.addresses));
        }
    }
    Ok(device_names)
}

/// Begins the capture process and returns a control block for the capture.
/// The input is a Parameters struct that contains the following information:
/// * device_id: The id of the network device to capture from
/// * timeout: The time after which the capture stops
/// * file_path: The path of the file where the captured packets will be saved
/// * filter: An optional filter to be applied to the captured packets (in BPF format - https://biot.com/capstats/bpf.html)
pub fn analyze_network(parameters: Parameters) -> Result<Arc<ControlBlock>, SnifferError> {
    let device_id = parameters.device_id;
    let main_device = Device::list().unwrap();
    let device = main_device.get(device_id).unwrap().clone();
    let mut cap =
        match match Capture::from_device(device){
            Ok(c) => c.promisc(true)
                .snaplen(5000)
                .timeout(1000)
                .open(),
            Err(e) => return Err(SnifferError::ConfigError(InvalidDeviceId(e)))
        } {
            Ok(c) => c,
            Err(e) => return Err(SnifferError::CaptureError(CaptureError::CaptureError(e)))
        };

    if let Some(filter) = &parameters.filter {
        if let Err(e) = cap.filter(filter, true) {
            return Err(SnifferError::ConfigError(InvalidFilter(e)));
        };
    }

    let control_block = ControlBlock::new();
    if !parameters.file_path.is_empty() {
        match control_block.set_output_file(parameters.file_path){
            Ok(_) => {},
            Err(e) => return Err(e)
        };
    }
    if parameters.timeout != 0 {
        control_block.set_timeout(parameters.timeout);
    }
    let control_block_clone = control_block.clone();

    control_block_clone.set_capture(cap);

    std::thread::spawn(move || {
        read_packets(control_block_clone);
    });
    Ok(control_block)
}

fn read_packets(control_block: Arc<ControlBlock>) {
    let report = Arc::new(Mutex::new(Report::default()));

    //create a thread pool to handle the packets
    let pool = ThreadPool::new(num_cpus::get());

    let report_clone_out = report.clone();

    let control_block_clone = control_block.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(u64::from(control_block_clone.get_timeout())));
            match control_block_clone.get_state() {
                CaptureState::Stopped() => (),
                CaptureState::Paused() => {
                    control_block_clone.wait();
                    continue;
                }
                CaptureState::Capturing() => {
                    match fs::write(control_block_clone.get_output_file(), report_clone_out.lock().unwrap().to_formatted_table().to_string()){
                        Ok(_) => (),
                        Err(_) => continue
                    }
                }
            };
        }
    });

    loop {
        match control_block.get_state() {
            CaptureState::Stopped() => break,
            CaptureState::Paused() => {
                control_block.wait();
                continue;
            }
            CaptureState::Capturing() => {
                match control_block.get_capture().next_packet() {
                    Ok(packet) => {
                        //recheck the state of the capture and discard data if it has come after it was paused or stopped
                        match control_block.get_state() {
                            CaptureState::Stopped() => (),
                            CaptureState::Paused() => (),
                            CaptureState::Capturing() => {
                                let packet_data = packet.data.to_owned();
                                let packet_header = packet.header.to_owned();
                                let report_copy = report.clone();
                                pool.execute(move || {
                                    match SlicedPacket::from_ethernet(&*packet_data) {
                                        Err(..) => {}
                                        Ok(sliced_packet) => {
                                            let mut result = MyPacket::new(Default::default(), Default::default(), Default::default(), None, None, Default::default(), Default::default(), Default::default());
                                            fill_timestamp_and_lenght(&packet_header, &mut result);
                                            fill_ip_address(&sliced_packet, &mut result);
                                            fill_protocol_and_ports(&sliced_packet, &mut result);
                                            report_copy.lock().unwrap().add_packet(result);
                                        }
                                    }
                                });
                            }
                        }
                    }
                    Err(e) => {
                        // match e {
                        //     //ignore only the timeout error, I wanted to use a timeout to be able to check the state of the capture
                        //     pcap::Error::TimeoutExpired => (),
                        //     _ => {
                        //         control_block.push_error(SnifferError::CaptureError(CaptureError::CaptureError(e)));
                        //         break;
                        //     }
                        // }
                        control_block.push_error(SnifferError::CaptureError(CaptureError::CaptureError(e)));
                    }
                }
            }
        }
    };

    pool.join();
}

fn fill_ip_address(packet: &SlicedPacket, dest_packet: &mut MyPacket) {
    match &packet.ip {
        Some(Ipv4(header, ..)) => {
            dest_packet.set_source(String::from(header.to_header().source.map(|it| { it.to_string() }).to_vec().join(".")));
            dest_packet.set_destination(String::from(header.to_header().destination.map(|it| { it.to_string() }).to_vec().join(".")));
        }
        Some(Ipv6(header, ..)) => {
            dest_packet.set_source(to_hex_string(4, header.to_header().source.to_vec()));
            dest_packet.set_destination(to_hex_string(4, header.to_header().destination.to_vec()));
        }
        None => {
            match &packet.link {
                Some(Ethernet2(header, ..)) => {
                    dest_packet.set_source(to_hex_string(2, header.to_header().source.to_vec()));
                    dest_packet.set_destination(to_hex_string(2, header.to_header().destination.to_vec()));

                    //ether type match
                    let ethertype = match header.ether_type() {
                        0x0800 => {
                            String::from("IPv4")
                        }
                        0x86DD => {
                            String::from("IPv6")
                        }
                        0x0806 => {
                            String::from("ARP")
                        }
                        0x8100 => {
                            String::from("VLAN")
                        }
                        0x8847 => {
                            String::from("MPLS")
                        }
                        _ => {
                            String::from("Unknown")
                        }
                    };
                    dest_packet.set_protocol(ethertype.clone());
                    dest_packet.set_info(ethertype);
                }
                None => {}
            }
        }
    }
}

fn fill_protocol_and_ports(packet: &SlicedPacket, dest_packet: &mut MyPacket) {
    let packet_copy = packet.clone();
    match packet_copy.transport {
        Some(val) => {
            match val {
                Udp(header_slice) => {
                    dest_packet.set_protocol(String::from("UDP"));
                    dest_packet.set_source_port(Some(header_slice.to_header().source_port.to_string()));
                    dest_packet.set_destination_port(Some(header_slice.to_header().destination_port.to_string()));
                }
                Tcp(header_slice) => {
                    dest_packet.set_protocol(String::from("TCP"));
                    dest_packet.set_source_port(Some(header_slice.to_header().source_port.to_string()));
                    dest_packet.set_destination_port(Some(header_slice.to_header().destination_port.to_string()));
                }
                Icmpv4(..) => {
                    dest_packet.set_protocol(String::from("ICMPv4"));
                    // dest_packet.set_info(slice.header().icmp_type.to_string());
                }
                Icmpv6(..) => {
                    dest_packet.set_protocol(String::from("ICMPv6"));
                    // dest_packet.set_info(slice.header().icmp_type.to_string());
                }
                Unknown(..) => {
                    dest_packet.set_protocol(String::from("Unknown"));
                    dest_packet.set_info(String::from("UNKNOWN"));
                }
            }
        }
        _ => {}
    }
}

fn fill_timestamp_and_lenght(packet: &PacketHeader, dest_packet: &mut MyPacket) {
    dest_packet.set_length(&packet.len);
    match &packet.ts {
        val => {
            dest_packet.set_timestamp(&val.tv_sec, &val.tv_usec);
        }
    }
}

fn to_hex_string(group_size: usize, address: Vec<u8>) -> String {
    hex::encode_upper(address)
        .chars()
        .collect::<Vec<char>>()
        .chunks(group_size)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(":")
}
