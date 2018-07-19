/* Copyright (c) 2018 Waldemar Augustyn */

#[cfg(debug_assertions)]
use chrono::Local;
use flexi_logger::Logger;
use log;
use std::io;

pub fn init(debug: bool) {
    Logger::with_env_or_str(if debug { "meadow=debug" } else { "meadow=info" })
        .format(log_formt)
        .start()
        .unwrap();
}

// no time stamps for releases
#[cfg(not(debug_assertions))]
fn log_formt(ww: &mut io::Write, rec: &log::Record) -> Result<(), io::Error> {
    let level = match rec.level() {
        log::Level::Info => "info",
        log::Level::Error => "ERR ",
        log::Level::Warn => "WARN",
        log::Level::Debug => "dbg ",
        log::Level::Trace => "trc ",
    };

    if level == "dbg " {
        write!(
            ww,
            "{:5} {}({}): {}",
            level,
            {
                let path = rec.file().unwrap_or("???.rs");
                &path[if let Some(ix) = &path.rfind('/') {
                          ix + 1
                      } else {
                          0
                      }..]
            },
            rec.line().unwrap_or(0),
            &rec.args()
        )
    } else {
        write!(ww, "{:5} {}", level, &rec.args())
    }
}

// print time stamps during development
#[cfg(debug_assertions)]
fn log_formt(ww: &mut io::Write, rec: &log::Record) -> Result<(), io::Error> {
    let level = match rec.level() {
        log::Level::Info => "info",
        log::Level::Error => "ERR ",
        log::Level::Warn => "WARN",
        log::Level::Debug => "dbg ",
        log::Level::Trace => "trc ",
    };

    if level == "dbg " {
        write!(
            ww,
            "{} {:5} {}({}): {}",
            Local::now().format("%H:%M:%S%.6f"),
            level,
            {
                let path = rec.file().unwrap_or("???.rs");
                &path[if let Some(ix) = &path.rfind('/') {
                          ix + 1
                      } else {
                          0
                      }..]
            },
            rec.line().unwrap_or(0),
            &rec.args()
        )
    } else {
        write!(
            ww,
            "{} {:5} {}",
            Local::now().format("%H:%M:%S%.6f"),
            level,
            &rec.args()
        )
    }
}
