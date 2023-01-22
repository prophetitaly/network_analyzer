use std::fs::{File, metadata};
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
            clearscreen::clear().expect("failed to clear screen");
            loop {
                println!("Scrivi: \n \
                - \"pause\" per fermare l'analisi\n \
                - \"resume\" per riprendere l'analisi \n \
                - \"exit\" per uscire \n \
                - \"device\" per elencare i dispositivi disponibili e sceglierne uno \n \
                - \"timeout\" per cambiare l'intervallo di generazione del report\n \
                - \"output\" per cambiare il percorso del file di output");
                let mut input = String::new();
                println!("Comando: ");
                io::stdin().read_line(&mut input).expect("Failed to read line");
                clearscreen::clear().expect("failed to clear screen");
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
                        cb.stop();
                        break;
                    }
                    "timeout" => {
                        clearscreen::clear().expect("failed to clear screen");
                        println!("Inserisci il nuovo timeout: ");
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).expect("Failed to read line");
                        match input.trim().parse::<u32>() {
                            Ok(timeout) => {
                                cb.set_timeout(timeout);
                                clearscreen::clear().expect("failed to clear screen");
                                println!("Timeout impostato a {}", timeout);
                            }
                            Err(_) => {
                                println!("Timeout non valido");
                                continue;
                            }
                        }
                    }
                    "output" => {
                        loop {
                            clearscreen::clear().expect("failed to clear screen");
                            println!("Inserisci il nuovo path del file di output: ");
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).expect("Failed to read line");
                            let output = input.trim().to_string();
                            match metadata(output.clone()) {
                                Ok(_) => {
                                    cb.set_output_file(output.clone());
                                    clearscreen::clear().expect("failed to clear screen");
                                    println!("Path del file di output impostato a {}", output);
                                    break;
                                },
                                Err(_) => {
                                    match File::create(output.clone()) {
                                        Ok(_) => {
                                            cb.set_output_file(output.clone());
                                            clearscreen::clear().expect("failed to clear screen");
                                            println!("Path del file di output impostato a {}", output);
                                            break;
                                        },
                                        Err(_) => {
                                            println!("Il path del file di output non è valido");
                                            continue;
                                        }
                                    };
                                }
                            }

                        }
                    }
                    "device" => {
                        loop {
                            clearscreen::clear().expect("failed to clear screen");
                            let devices = get_devices();
                            if devices.is_err() {
                                println!("Errore nel caricamento dei device: {}", devices.err().unwrap());
                                break;
                            }
                            let devices = devices.unwrap();
                            let dev_clone = devices.clone();
                            for d in devices.iter().enumerate() {
                                println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
                            }
                            println!("Inserisci il nuovo device id: ");
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).expect("Failed to read line");
                            let device_id = input.trim().parse::<usize>().unwrap();
                            if dev_clone.len() < device_id {
                                println!("Device id non valido");
                                continue;
                            }
                            cb.set_device(device_id - 1);
                            clearscreen::clear().expect("failed to clear screen");
                            println!("Device id impostato a {}", device_id);
                            break;
                        }
                    }
                    "filter" => {
                        clearscreen::clear().expect("failed to clear screen");
                        println!("Inserisci il nuovo filtro: ");
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).expect("Failed to read line");
                        let filter = input.trim().to_string();
                        if cb.set_filter(filter.clone()).is_err() {
                            println!("Filtro non valido");
                            continue;
                        }
                        clearscreen::clear().expect("failed to clear screen");
                        println!("Filtro impostato");
                    }
                    _ => {
                        println!("Comando non riconosciuto");
                    }
                }
            }
        }
    }
}