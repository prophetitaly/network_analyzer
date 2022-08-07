use std::io;
use network_analyzer::get_devices;

fn main() {

    for d in get_devices().iter().enumerate() {
        println!("{}) {} {:?}", d.0 + 1, d.1.0, d.1.1);
    }

    //take input from terminal
    println!("Enter the number of the device you want to analyze: \n");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input: usize = input.trim().parse().unwrap();

    network_analyzer::analyze_network(input - 1);
}