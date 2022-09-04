mod config;
mod device;
mod eap;

use clap::Parser;
use log::debug;
use pnet::datalink;
use std::{fs, net::Ipv4Addr};

use crate::{
    config::{AuthConfig, UserConfig},
    device::Device,
};

fn init_log4rs() {
    use log::LevelFilter;
    use log4rs::{
        append::{console::ConsoleAppender, file::FileAppender},
        config::{Appender, Root},
        encode::pattern::PatternEncoder,
        Config,
    };
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

#[derive(Debug, clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    iface: String,
}

fn main() {
    let args = Args::parse();
    init_log4rs();
    let iface_name = args.iface;
    let ifaces = datalink::interfaces();
    let iface = ifaces
        .into_iter()
        .filter(|iface| iface.name == iface_name)
        .next()
        .unwrap();
    debug!("mac: {}", iface.mac.unwrap());
    debug!("available ips: {:?}", iface.ips);

    let contents = fs::read_to_string("user-config.toml").unwrap();
    let user_config: UserConfig = toml::from_str(&contents).unwrap();

    let auth_config = AuthConfig {
        username: user_config.username,
        password: user_config.password,
        hostname: user_config.hostname,
        auth_ip: user_config.auth_ip.parse::<Ipv4Addr>().unwrap(),
        mac: iface.mac.unwrap(),
        iface,
        dns: "222.201.130.33".into(), // one of SCUT DNS
    };
    let device = Device::new(auth_config);
}
