use std::{env};
use network_analyzer::{analyze_network, get_devices};
use network_analyzer::parameters::Parameters;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    let mut parameters = Parameters::new();
    if args.len() > 2 {
            for (index, arg) in args.iter().enumerate() {
                if arg.starts_with("-") {
                    let (key, value) = arg.split_at(1);
                    match value {
                        "d" => parameters.set_device_id(args[index+1].parse::<usize>().unwrap()),
                        "t" => parameters.set_timeout(args[index+1].parse::<u32>().unwrap()),
                        "f" => parameters.set_file_path(args[index+1].to_string()),
                        "p" => parameters.set_protocol(args[index+1].to_string()),
                        "src" => parameters.set_source(args[index+1].to_string()),
                        "dst" => parameters.set_destination(args[index+1].to_string()),
                        "srcp" => parameters.set_source_port(args[index+1].to_string()),
                        "dstp" => parameters.set_destination_port(args[index+1].to_string()),
                        "adapters" => {
                            panic!("Wrong parameter {}", key);
                        }
                        _ => panic!("Unknown parameter {}", key),
                    }
                }
            }
            if !parameters.file_path.is_empty() {
                analyze_network(parameters);
            } else {
                panic!("No file path provided!")
            }
    }else if args.len() == 1 && args[1].starts_with("-adapters") {
        for d in get_devices().iter().enumerate() {
            println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
        }
    } else {
        panic!("No file path provided!")
    }

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