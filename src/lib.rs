mod packet;
mod parameters;

use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::{ SlicedPacket };
use etherparse::LinkSlice::Ethernet2;
use etherparse::TransportSlice::{Icmpv4, Icmpv6, Tcp, Udp, Unknown};
use pcap::{Activated, Device, Capture, PacketHeader, Address};
use crate::packet::Packet;

pub fn get_devices() -> Vec<(String, Vec<Address>)> {
    let devices = Device::list().unwrap();
    let mut device_names: Vec<(String, Vec<Address>)> = Vec::new();
    for device in devices {
        device_names.push((device.desc.unwrap().to_string(), device.addresses));
    }
    device_names
}

pub fn analyze_network(device_id: usize) {
    let main_device = Device::list().unwrap();
    let device = main_device.get(device_id).unwrap().clone();
    let cap = Capture::from_device(device).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open().unwrap();

    // while let Ok(packet) = cap.next() {
    //     println!("received packet! {:?}", packet);
    // }
    read_packets(cap)
}

fn read_packets<T: Activated>(mut capture: Capture<T>) {
    while let Ok(packet) = capture.next() {
        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(sliced_packet) => {
                let mut result = Packet::new(Default::default(), Default::default(), Default::default(), Default::default(), Default::default(), Default::default(), Default::default(), Default::default());
                fill_timestamp_and_lenght(&packet.header, &mut result);
                fill_ip_address(&sliced_packet, &mut result);
                fill_protocol_and_ports(&sliced_packet, &mut result);
                println!("{:?}", result);
            }
        }
    }
}

fn fill_ip_address(packet: &SlicedPacket, dest_packet: &mut Packet) {
    match &packet.ip {
        Some(Ipv4(header, ..)) => {
            dest_packet.set_source(String::from(header.to_header().source.map(|it| { it.to_string() }).to_vec().join(".")));
            dest_packet.set_destination(String::from(header.to_header().destination.map(|it| { it.to_string() }).to_vec().join(".")));
        }
        Some(Ipv6(header, ..)) => {
            dest_packet.set_source(to_hex_string(header.to_header().source.to_vec()));
            dest_packet.set_destination(to_hex_string(header.to_header().destination.to_vec()));
        }
        None => {
            match &packet.link {
                Some(Ethernet2(header, ..)) => {
                    dest_packet.set_source(to_hex_string(header.to_header().source.to_vec()));
                    dest_packet.set_destination(to_hex_string(header.to_header().destination.to_vec()));

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

fn fill_protocol_and_ports(packet: &SlicedPacket, dest_packet: &mut Packet) {
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

fn fill_timestamp_and_lenght(packet: &PacketHeader, dest_packet: &mut Packet) {
    dest_packet.set_length(&packet.len);
    match &packet.ts {
        val => {
            dest_packet.set_timestamp(&val.tv_sec, &val.tv_usec);
        }
    }
}

fn to_hex_string(address: Vec<u8>) -> String {
    hex::encode_upper(address)
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(":")
}
