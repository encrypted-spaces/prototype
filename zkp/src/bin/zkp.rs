use std::{env, process};

use encrypted_spaces_zkp::demo::{human, setup_logging, DEMOS};

fn main() {
    setup_logging();
    match parse_args() {
        CliArgs::Help => {
            print_help();
        }
        CliArgs::Run {
            demo_name,
            input_size,
        } => {
            let proving_func = DEMOS
                .iter()
                .find(|demo| demo.name == demo_name)
                .map(|demo| demo.run)
                .unwrap_or_else(|| {
                    eprintln!("Unknown demo '{demo_name}'. Available demos:");
                    list_demos();
                    process::exit(1);
                });

            let proof = proving_func(input_size);
            println!("Demo: {demo_name}");
            println!("Input size: {input_size}");
            println!("Serialized proof length: {}", human(proof.len()));
        }
    }
}

enum CliArgs {
    Help,
    Run {
        demo_name: String,
        input_size: usize,
    },
}

fn parse_args() -> CliArgs {
    let mut args = env::args();
    let exe = args.next().unwrap_or_else(|| "zkp".into());
    let mut rest: Vec<String> = args.collect();

    match rest.first().map(String::as_str) {
        Some("-h") | Some("--help") => return CliArgs::Help,
        None => {
            eprintln!("Usage: {exe} <demo-name> <input-size>");
            eprintln!();
            print_help();
            process::exit(1);
        }
        _ => {}
    }

    // Be forgiving if someone passes an extra leading arg (e.g. cargo run zkp_demo <demo> <n>).
    if rest.len() >= 2 && !is_known_demo(&rest[0]) && is_known_demo(&rest[1]) {
        rest.remove(0);
    }

    let demo_name = rest.first().cloned().unwrap_or_default();

    let value = rest.get(1).cloned().unwrap_or_else(|| {
        eprintln!("Usage: {exe} <demo-name> <input-size>");
        eprintln!();
        print_help();
        process::exit(1);
    });

    let input_size = value.parse::<usize>().unwrap_or_else(|err| {
        eprintln!("Invalid input size '{value}': {err}");
        process::exit(1);
    });

    CliArgs::Run {
        demo_name,
        input_size,
    }
}

fn print_help() {
    println!("Usage: zkp <demo-name> <input-size>");
    println!("Example: cargo run -p encrypted-spaces-zkp --bin zkp -- keccak_baby_bear_zk 128");
    println!();
    println!("Available demos:");
    list_demos();
}

fn list_demos() {
    for demo in DEMOS {
        println!(
            "  - {} (default input size: {})",
            demo.name, demo.default_input_size
        );
    }
}

fn is_known_demo(name: &str) -> bool {
    DEMOS.iter().any(|demo| demo.name == name)
}
