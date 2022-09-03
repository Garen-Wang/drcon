use log::{debug, info, LevelFilter};
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    Config,
};

fn init_log4rs() {
    let file_appender = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h([{d(%Y-%m-%d %H:%M:%S)}][{l}][{T}] {m}{n})}",
        )))
        .build("log/output.log")
        .unwrap();
    let console_appender = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[{t}] {h({l})} {M} - {m}{n}")))
        .build();
    let log_config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(file_appender)))
        .appender(Appender::builder().build("console", Box::new(console_appender)))
        .build(
            Root::builder()
                .appender("file")
                .appender("console")
                .build(LevelFilter::Debug),
        )
        .unwrap();
    log4rs::init_config(log_config).unwrap();
    debug!("log4rs finish initialization");
}

fn main() {
    init_log4rs();
    println!("Hello, world!");
    info!("nice");
}
