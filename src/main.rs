mod config;
mod device;
mod eap;

use clap::Parser;
use log::debug;
use pnet::datalink;
use std::{fs, net::Ipv4Addr, sync::Arc, thread, time::Duration};

use crate::{
    config::{AuthConfig, UserConfig},
    device::Device,
    eap::{EAPContext, EAPStatus},
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
    // debug!("available ips: {:?}", iface.ips);

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
    let device = Arc::new(Device::new(&auth_config));
    let eap_context = EAPContext::new(device, &auth_config);
    eap_context.send_eapol_logoff().unwrap();
    thread::sleep(Duration::from_secs(1));
    eap_context.send_eapol_start().unwrap();
    let request_identity = eap_context.receive_data_until();
    let (id, remote_mac) = match request_identity {
        EAPStatus::RequestIdentity { id, remote_mac } => (id, remote_mac),
        _ => {
            panic!("unexpected eap status: request identity expected");
        }
    };
    debug!("id: {}, remote mac: {:?}", id, remote_mac);
    thread::sleep(Duration::from_secs(1));
    eap_context.send_response_identity(id, remote_mac).unwrap();
    let request_md5_challenge = eap_context.receive_data_until();
    let (id, md5_value) = match request_md5_challenge {
        EAPStatus::RequestMD5Challenge { id, md5_value } => (id, md5_value),
        _ => {
            panic!("unexpected eap status: requeset md5 challenge expected");
        }
    };
    debug!("id: {}, md5 value: {:?}", id, md5_value);
}
