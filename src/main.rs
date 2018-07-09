/* Copyright (c) 2018 Waldemar Augustyn */

use std::env;

fn main() {

    let args: Vec<String> = env::args().collect();

/* good

    let pgm = &args[0][match &args[0].rfind('/') {
                Some(ix) => ix+1,
                None => 0,
        }..];
*/

    let pgm = &args[0][ if let Some(ix) = &args[0].rfind('/') { ix + 1 } else { 0 }  .. ];


    println!("pgm: {}, args: {:?}", pgm, args);
}
