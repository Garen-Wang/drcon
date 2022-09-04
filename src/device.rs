use std::{cell::RefCell, io, net::Ipv4Addr};

use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    util::MacAddr,
};

use crate::config::AuthConfig;

/// device is used to send and receive in the real network level
pub struct Device {
    pub iface: NetworkInterface,
    pub mac: MacAddr,
    pub auth_ip: Ipv4Addr,
    pub tx: RefCell<Box<dyn DataLinkSender>>,
    pub rx: RefCell<Box<dyn DataLinkReceiver>>,
}

impl Device {
    pub fn new(config: AuthConfig) -> Self {
        let iface = config.iface;
        let channel = datalink::channel(&iface, Default::default())
            .expect("unable to establish network channel");
        let (tx, rx) = match channel {
            datalink::Channel::Ethernet(tx, rx) => (tx, rx),
            _ => panic!("unable to establish network channel"),
        };
        Device {
            iface,
            mac: config.mac,
            auth_ip: config.auth_ip,
            tx: RefCell::new(tx),
            rx: RefCell::new(rx),
        }
    }

    pub fn send(&self, data: Vec<u8>) -> io::Result<()> {
        let mut tx = self.tx.borrow_mut();
        tx.send_to(&data, None).unwrap()?;
        Ok(())
    }

    pub fn receive(&self) -> io::Result<Vec<u8>> {
        let mut rx = self.rx.borrow_mut();
        Ok(rx.next()?.to_vec())
    }
}
