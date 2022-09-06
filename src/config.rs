use std::net::Ipv4Addr;

use pnet::{datalink::NetworkInterface, util::MacAddr};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub auth_ip: String,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    pub dns: String,
    pub hostname: String,
    pub auth_ip: Ipv4Addr,
    pub mac: MacAddr,
    pub iface: NetworkInterface,
}
