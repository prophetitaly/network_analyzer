use std::io;
use network_analyzer::{analyze_network, get_devices};
use network_analyzer::parameters::Parameters;

use clap::{Args, Parser, Subcommand};

/// Network analyzer
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct NetworkAnalyzer {
    #[clap(subcommand)]
    pub subcommand: Options,
}

#[derive(Debug, Subcommand)]
pub enum Options {
    /// Get the network devices
    Devices(Devices),

    /// Begin analyzing the network
    Parse(ParseCommand),
}

#[derive(Debug, Args)]
pub struct Devices {}

#[derive(Debug, Args)]
pub struct ParseCommand {
    /// Network adapter id
    #[clap(short, long, value_parser, default_value = "0")]
    device_id: usize,

    /// Timeout after which it stops sniffing
    #[clap(short, long, value_parser, default_value_t = 5)]
    timeout: u32,

    /// Output file path
    #[clap(short, long, value_parser)]
    output: String,

    /// Filter in standardized BPF language to be applied to the sniffed packets
    #[clap(short, long, value_parser)]
    filter: Option<String>,
}

fn main() {
    let args = NetworkAnalyzer::parse();
    match args.subcommand {
        Options::Devices(_devices) => {
            let devices = get_devices();
            if devices.is_err() {
                println!("Error: {}", devices.err().unwrap());
                return;
            }
            for d in devices.unwrap().iter().enumerate() {
                println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
            }
        }
        Options::Parse(parse_command) => {
            let parameters = Parameters {
                device_id: parse_command.device_id - 1,
                timeout: parse_command.timeout,
                file_path: parse_command.output,
                filter: parse_command.filter,
            };
            let cb_result = analyze_network(parameters);
            if cb_result.is_err() {
                println!("Error: {}", cb_result.err().unwrap());
                return;
            }
            let cb = cb_result.unwrap();
            clear_screen();
            loop {
                println!("Write: \n \
                - \"pause\" for pausing the capture\n \
                - \"resume\" for resuming the capture \n \
                - \"exit\" to exit \n \
                - \"device\" to list all devices and choose one \n \
                - \"timeout\" to change the report generation interval\n \
                - \"output\" to change the output file path\n");
                let mut input = String::new();
                println!("Command: ");
                io::stdin().read_line(&mut input).expect("Failed to read line");
                clear_screen();
                match input.trim() {
                    "pause" => {
                        cb.pause();
                        println!("Analysis paused");
                    }
                    "resume" => {
                        cb.resume();
                        println!("Analysis resumed");
                    }
                    "exit" => {
                        cb.stop();
                        break;
                    }
                    "timeout" => {
                        loop {
                            clear_screen();
                            println!("Insert the new timeout: ");
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).expect("Failed to read line");
                            match input.trim().parse::<u32>() {
                                Ok(timeout) => {
                                    cb.set_timeout(timeout);
                                    clear_screen();
                                    println!("Timeout set at {}", timeout);
                                }
                                Err(_) => {
                                    println!("Timeout not valid");
                                    continue;
                                }
                            }
                        }

                    }
                    "output" => {
                        loop {
                            clear_screen();
                            println!("Insert the new output file path: ");
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).expect("Failed to read line");
                            let output = input.trim().to_string();
                            match cb.set_output_file(output.clone()) {
                                Ok(_) => {
                                    clear_screen();
                                    println!("Path of the output file set to {}", output);
                                    break;
                                }
                                Err(e) => {
                                    clear_screen();
                                    println!("Error in setting the output file path: {}", e);
                                    continue;
                                }
                            }
                        }
                    }
                    "device" => {
                        loop {
                            clear_screen();
                            let devices = get_devices();
                            if devices.is_err() {
                                println!("Error in loading devices: {}", devices.err().unwrap());
                                break;
                            }
                            let devices = devices.unwrap();
                            for d in devices.iter().enumerate() {
                                println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
                            }
                            println!("Insert the new device id: ");
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).expect("Failed to read line");
                            let device_id = input.trim().parse::<usize>().unwrap();
                            match cb.set_device(device_id - 1) {
                                Ok(_) => {
                                    clear_screen();
                                    println!("Device id set to {}", device_id);
                                    break;
                                }
                                Err(e) => {
                                    clear_screen();
                                    println!("Error in setting the new device: {}", e);
                                    continue;
                                }
                            }
                        }
                    }
                    "filter" => {
                        clearscreen::clear().expect("failed to clear screen");
                        println!("Insert the new filter: ");
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).expect("Failed to read line");
                        let filter = input.trim().to_string();
                        if cb.set_filter(filter.clone()).is_err() {
                            println!("Filtro not valid");
                            continue;
                        }
                        clear_screen();
                        println!("Filtro set");
                    }
                    _ => {
                        println!("Command not valid");
                    }
                }
            }
        }
    }
}

fn clear_screen() {
    match clearscreen::clear() {
        Ok(_) => {}
        Err(_) => {}
    };
}