mod packet;
pub mod parameters;
mod report;

use std::fs;
use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::{SlicedPacket};
use etherparse::LinkSlice::Ethernet2;
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use pcap::{Device, Capture, PacketHeader, Address, Active};
use threadpool::ThreadPool;
use crate::packet::Packet as MyPacket;
use crate::parameters::Parameters;
use crate::report::Report;

#[derive(Eq, PartialEq, Clone)]
pub enum CaptureState {
    Capturing(),
    Paused(),
    Stopped(),
}

pub struct ControlBlock {
    m: Mutex<CaptureState>,
    cv: Condvar,
}

impl ControlBlock {
    pub fn new() -> Arc<ControlBlock> {
        Arc::new(ControlBlock {
            m: Mutex::new(CaptureState::Capturing()),
            cv: Condvar::new(),
        })
    }

    pub fn get_state(&self) -> CaptureState {
        let state = self.m.lock().unwrap();
        state.clone()
    }

    pub fn pause(&self) {
        let mut state = self.m.lock().unwrap();
        *state = CaptureState::Paused();
        self.cv.notify_all();
    }

    pub fn resume(&self) {
        let mut state = self.m.lock().unwrap();
        *state = CaptureState::Capturing();
        self.cv.notify_all();
    }

    pub fn stop(&self) {
        let mut state = self.m.lock().unwrap();
        *state = CaptureState::Stopped();
        self.cv.notify_all();
    }

    pub fn wait(&self) {
        let mut state = self.m.lock().unwrap();
        while *state == CaptureState::Paused() {
            state = self.cv.wait(state).unwrap();
        }
    }
}

pub fn get_devices() -> Vec<(String, Vec<Address>)> {
    let devices = Device::list().unwrap();
    let mut device_names: Vec<(String, Vec<Address>)> = Vec::new();
    for device in devices {
        device_names.push((device.desc.unwrap().to_string(), device.addresses));
    }
    device_names
}

//TODO: Scrivere tutte le funzioni come Result<T, E>
pub fn analyze_network(parameters: Parameters) -> Arc<ControlBlock> {
    let device_id = parameters.device_id;
    let main_device = Device::list().unwrap();
    let device = main_device.get(device_id).unwrap().clone();
    let mut cap = Capture::from_device(device).unwrap()
        .promisc(true)
        .snaplen(5000)
        .timeout(1000)
        .open()
        .unwrap();

    if let Some(filter) = &parameters.filter {
        cap
            .filter(filter, true)
            .expect("Filters invalid, please check the documentation.");
    }

    let control_block = ControlBlock::new();
    let control_block_clone = control_block.clone();
    std::thread::spawn(move || {
        read_packets(cap, parameters, control_block_clone);
    });
    control_block
}

fn read_packets(mut capture: Capture<Active>, parameters: Parameters, control_block: Arc<ControlBlock>) {
    let report = Arc::new(Mutex::new(Report::default()));

    //create a thread pool to handle the packets
    let pool = ThreadPool::new(num_cpus::get());

    let report_clone_out = report.clone();

    let control_block_clone = control_block.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(u64::from(parameters.timeout)));
            match control_block_clone.get_state() {
                CaptureState::Stopped() => (),
                CaptureState::Paused() => {
                    control_block_clone.wait();
                    continue;
                },
                CaptureState::Capturing() => {
                    let report_string = report_clone_out.lock().unwrap().clone().get_report_lines().iter()
                        .fold(String::new(), |result, rls| {
                            result + "\n" + &rls.1.to_string()
                        });
                    // .collect::<Vec<String>>().join("\n");
                    let formatted_report = "Timestamp first   Timestamp last    Address 1                                 Address 2                                 Protocols                              Total tx size in Bytes        \n";
                    fs::write(&parameters.file_path, formatted_report.to_string() + &report_string).expect("Wrong output file path!");
                }
            }
        }
    });

    loop {
        //TODO: se non arrivano pacchetti e il timer scatta, il thread rimane comunque
        // bloccato finchè arriva almeno un pacchetto a causa di capture.next() #risolvere
        // possibile soluzione: usare .timeout() su capture

        match control_block.get_state() {
            CaptureState::Stopped() => break,
            CaptureState::Paused() => {
                control_block.wait();
                continue;
            }
            CaptureState::Capturing() => {
                match capture.next_packet() {
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
                                            let mut result = MyPacket::new(Default::default(), Default::default(), Default::default(), Default::default(), Default::default(), Default::default(), Default::default(), Default::default());
                                            fill_timestamp_and_lenght(&packet_header, &mut result);
                                            fill_ip_address(&sliced_packet, &mut result);
                                            fill_protocol_and_ports(&sliced_packet, &mut result);
                                            // println!("{:?}", result);
                                            report_copy.lock().unwrap().add_packet(result);
                                        }
                                    }
                                });
                            }
                        }
                    },
                    Err(..) => {}
                }
            },
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
                    dest_packet.set_source_port(header_slice.to_header().source_port.to_string());
                    dest_packet.set_destination_port(header_slice.to_header().destination_port.to_string());
                }
                Tcp(header_slice) => {
                    dest_packet.set_protocol(String::from("TCP"));
                    dest_packet.set_source_port(header_slice.to_header().source_port.to_string());
                    dest_packet.set_destination_port(header_slice.to_header().destination_port.to_string());
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
