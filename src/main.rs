use std::env;

mod util;

fn print_prg_info() {
    let prg_info = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let prg_authors = format!("(c) 2023 by {}", env!("CARGO_PKG_AUTHORS"));
    let prg_description = format!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!("{} {}", prg_info, prg_authors);
    println!("{}", prg_description);
    println!();
}


fn print_help() {
    print_prg_info();
    println!("Usage: cat cves.txt | kevin [options]");
    println!("Options:");
    println!("  -h, --help\t\t\tPrint this help");
    println!("  -v, --version\t\t\tPrint version information");
    println!();
}


fn main() {
    util::check_for_stdin();

    let args: Vec<String> = env::args().collect();

    args.iter().for_each(|arg| match arg.as_str() {
        "-h" | "--help" => {
            print_help();
            std::process::exit(0);
        }
        "-v" | "--version" => {
            print_prg_info();
            std::process::exit(0);
        }
        _ => {}
    });

    util::warn("Use with caution. You are responsible for your actions.".to_string());
    util::warn("Developers assume no liability and are not responsible for any misuse or damage.".to_string());
    
    let lines = util::get_stdio_lines();

    let _ = kevin::run(&lines).unwrap();
}