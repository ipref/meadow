/* Copyright (c) 2018 Waldemar Augustyn */

use clap::{App, Arg, SubCommand};
use std::process;

pub struct Config {
    pub debug: bool,
    pub trace: bool,
    pub gw_port: u16,
    pub gw_mtu: u32,
    pub tun_mtu: u32,
    pub tun_hdrlen: usize,
}

pub const OPTLEN: usize = 8 + 4 + 4 + 16 + 16; // udphdr + encap + opt + ref + ref

pub fn new() -> Config {
    // read cli

    let cli = App::new(crate_name!())
                    .version(crate_version!())
                    .about("Run IPREF gateway in user space")
                    .help_message("display this help message")
                    .version_message("display version")
                    .arg(Arg::with_name("config")
                        .short("c")
                        .long("config")
                        .value_name("CONFIG")
                        .default_value("/etc/ipref/ipref.conf")
                        .help("absolute path to config file")
                        .takes_value(true))
                    .arg(Arg::with_name("debug")
                        .short("d")
                        .long("debug")
                        .help("enable debug"))
                    .arg(Arg::with_name("trace")
                        .short("t")
                        .long("trace")
                        .help("enable trace (implies --debug)"))
                    .subcommand(SubCommand::with_name("start")
                        .about("start IPREF gateway"))
                    .subcommand(SubCommand::with_name("help")   // override default help subcommand
                        .about("display usage"))                // have to manually call after override
                .get_matches();

    let cmd = if let Some(name) = cli.subcommand_name() {
        name
    } else {
        "help"
    };
    if cmd != "start" {
        println!("{}", cli.usage()); // "start" missing, print help
        process::exit(0);
    }

    // read config file

    //let config = cli.value_of("config").unwrap();

    // construct config

    Config {
        debug: cli.is_present("debug"),
        trace: cli.is_present("trace"),
        gw_port: 1045,
        gw_mtu: 1500,
        tun_mtu: 1500 - OPTLEN as u32,
        tun_hdrlen: 4,
    }
}
