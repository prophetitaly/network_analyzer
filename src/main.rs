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

//TODO: documentazione argomenti non stampata bene

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
            let cb_result = analyze_network(Parameters {
                device_id: parse_command.device_id - 1,
                timeout: parse_command.timeout,
                file_path: parse_command.output,
                filter: parse_command.filter,
            });
            if cb_result.is_err() {
                println!("Error: {}", cb_result.err().unwrap());
                return;
            }
            let cb = cb_result.unwrap();
            loop {
                println!("\nScrivi: \n - \"pause\" per fermare l'analisi \n - \"resume\" per riprendere l'analisi \n - \"exit\" per uscire");
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                match input.trim() {
                    "pause" => {
                        cb.pause();
                        println!("Analisi in pausa");
                    }
                    "resume" => {
                        cb.resume();
                        println!("Analisi ripresa");
                    }
                    "exit" => {
                        break;
                    }
                    _ => {
                        println!("Comando non riconosciuto");
                    }
                }
            }
        }
    }
}