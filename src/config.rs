/* Copyright (c) 2018 Waldemar Augustyn */

use clap::{App, Arg, SubCommand};
use std::process;

pub struct Config {
    pub debug: bool,
    pub port: u16,
}

pub fn get() -> Config {
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
                    .args_from_usage("-d, --debug 'enable debug'")
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
        port: 1045,
    }
}
