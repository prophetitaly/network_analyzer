// use std::{env};
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
pub struct Devices {

}

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
            for d in get_devices().iter().enumerate() {
                println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
            }
        }
        Options::Parse(parse_command) => {
            analyze_network(Parameters {
                device_id: parse_command.device_id - 1,
                timeout: parse_command.timeout,
                file_path: parse_command.output,
                filter: parse_command.filter,
            });
        }
    }

    // let args: Vec<String> = env::args().collect();
    // println!("{:?}", args);
    // let mut parameters = Parameters::new();
    // if args.len() > 2 {
    //         for (index, arg) in args.iter().enumerate() {
    //             if arg.starts_with("-") {
    //                 let (key, value) = arg.split_at(1);
    //                 match value {
    //                     "d" => parameters.set_device_id(args[index+1].parse::<usize>().unwrap() - 1),
    //                     "t" => parameters.set_timeout(args[index+1].parse::<u32>().unwrap()),
    //                     "o" => parameters.set_file_path(args[index+1].to_string()),
    //                     "f" => parameters.set_protocol(args[index+1].to_string()),
    //                     "adapters" => {
    //                         panic!("Wrong parameter {}", key);
    //                     }
    //                     _ => panic!("Unknown parameter {}", key),
    //                 }
    //             }
    //         }
    //         if !parameters.file_path.is_empty() {
    //             analyze_network(parameters);
    //         } else {
    //             panic!("No file path provided!")
    //         }
    // }else if args.len() == 1 && args[1].starts_with("-adapters") {
    //     for d in get_devices().iter().enumerate() {
    //         println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
    //     }
    // } else {
    //     panic!("No file path provided!")
    // }

    // println!("Enter the number of the device you want to analyze: \n");
    // let mut input = String::new();
    // io::stdin().read_line(&mut input).unwrap();
    // let input: usize = input.trim().parse().unwrap();
    //
    // let mut parameters = Parameters::new();
    // parameters.device_id = Some(input - 1);
    //
    // analyze_network(parameters);
}