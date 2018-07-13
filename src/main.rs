/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;

mod config;

fn main() {

    /* Get config
     *
     *  Ideally, cfg would be acessible globally from any thread without locks
     *  and without fear.
     *
     *  Currently, rust makes such an arrangement very difficult to implement
     *  without degrading to 'unsafe'. For now, we're going to pass cfg around
     *  as a parameter.
     */

    let cfg = config::get();

    println!("configuration:");
    println!("    port:   {}", cfg.port);
    println!("    debug:  {}", cfg.debug);
}
