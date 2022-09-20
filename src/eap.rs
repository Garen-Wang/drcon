use std::{io, sync::Arc};

use bytes::{BufMut, Bytes, BytesMut};
use hex_literal::hex;
use log::{debug, error};
use pnet::util::MacAddr;

use crate::{config::AuthConfig, device::Device};

// Destination MAC for EAPOL Start and Logoff
static QUERY_MAC: MacAddr = MacAddr(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03);
pub struct EAPContext {
    device: Arc<Device>,
    config: AuthConfig,
}

pub enum EAPStatus {
    RequestIdentity { id: u8, remote_mac: MacAddr },
    RequestMD5Challenge { id: u8, md5_value: Vec<u8> },
    Success,
    Failure,
}

pub trait Header
where
    Self: Sized,
{
    fn from_data(data: &[u8]) -> Option<Self>;
    fn write_to_data(&self, data: &mut BytesMut);
}

fn put_mac(data: &mut BytesMut, mac: MacAddr) {
    data.put_u8(mac.0);
    data.put_u8(mac.1);
    data.put_u8(mac.2);
    data.put_u8(mac.3);
    data.put_u8(mac.4);
    data.put_u8(mac.5);
}

pub struct HeaderEth {
    dest_mac: MacAddr,
    src_mac: MacAddr,
    ver: u16, // 0x888e
}
impl Header for HeaderEth {
    fn from_data(data: &[u8]) -> Option<Self> {
        let mut dest_mac: [u8; 6] = Default::default();
        dest_mac.copy_from_slice(&data[6..12]);
        let mut src_mac: [u8; 6] = Default::default();
        src_mac.copy_from_slice(&data[6..12]);
        let mut eth_type: [u8; 2] = Default::default();
        eth_type.copy_from_slice(&data[12..14]);
        let eth_type = u16::from_be_bytes(eth_type);
        if eth_type == 0x888e {
            Some(HeaderEth {
                dest_mac: dest_mac.into(),
                src_mac: src_mac.into(),
                ver: eth_type,
            })
        } else {
            None
        }
    }

    fn write_to_data(&self, data: &mut BytesMut) {
        put_mac(data, self.dest_mac);
        put_mac(data, self.src_mac);
        data.put_u16(self.ver);
    }
}

pub struct Header8021X {
    ver: u8, // 0x01: 802.1X-2001
    typ: u8, // 0x00: package
    len: u16,
}
impl Header for Header8021X {
    fn from_data(data: &[u8]) -> Option<Self> {
        let eapol_ver = data[14];
        let eapol_type = data[15];
        let mut eapol_len: [u8; 2] = Default::default();
        eapol_len.copy_from_slice(&data[16..18]);
        let eapol_len = u16::from_be_bytes(eapol_len);
        Some(Header8021X {
            ver: eapol_ver,
            typ: eapol_type,
            len: eapol_len,
        })
    }

    fn write_to_data(&self, data: &mut BytesMut) {
        data.put_u8(self.ver);
        data.put_u8(self.typ);
        data.put_u16(self.len);
    }
}

pub enum EAPCont {
    Identity(Vec<u8>),
    MD5Challenge {
        value_size: u8,
        md5_value: Vec<u8>,
        extra_data: Vec<u8>,
    },
}
impl Header for EAPCont {
    fn from_data(data: &[u8]) -> Option<Self> {
        let mut eap_len: [u8; 2] = Default::default();
        eap_len.copy_from_slice(&data[20..22]);
        let eap_len = u16::from_be_bytes(eap_len);
        let eap_code = data[18];
        let eap_type = data[22];
        // request identity: nothing
        // response identity: only identity
        // md5 challenge: value size, md5 value, extra data
        match eap_type {
            1 => match eap_code {
                1 => None,
                2 => {
                    let identity = &data[23..44];
                    Some(EAPCont::Identity(identity.to_vec()))
                }
                _ => panic!("unreachable"),
            },
            4 => {
                assert_eq!(eap_len, 16 + 4 + 6);
                let md5_value_size = data[23];
                let md5_value = &data[24..40];
                let extra_data = match eap_code {
                    1 => &data[40..44],
                    2 => &data[40..61],
                    _ => panic!("unreachable"),
                };
                Some(EAPCont::MD5Challenge {
                    value_size: md5_value_size,
                    md5_value: md5_value.to_vec(),
                    extra_data: extra_data.to_vec(),
                })
            }
            _ => {
                error!("unknown eap type: {}", eap_type);
                None
            }
        }
    }

    fn write_to_data(&self, data: &mut BytesMut) {
        match self {
            EAPCont::Identity(identity) => {
                data.put_slice(&identity);
            }
            EAPCont::MD5Challenge {
                value_size,
                md5_value,
                extra_data,
            } => {
                data.put_u8(*value_size);
                data.put_slice(md5_value);
                data.put_slice(extra_data);
            }
        }
    }
}
pub struct HeaderEAP {
    code: u8,
    id: u8,
    len: u16,
    typ: u8,
    cont: Option<EAPCont>,
}
impl Header for HeaderEAP {
    fn from_data(data: &[u8]) -> Option<Self> {
        let eap_code = data[18];
        let eap_id = data[19]; // a pair of eap share the same ID
        let mut eap_len: [u8; 2] = Default::default();
        eap_len.copy_from_slice(&data[20..22]);
        let eap_len = u16::from_be_bytes(eap_len);
        let eap_type = data[22];
        let eap_cont = EAPCont::from_data(data);
        Some(HeaderEAP {
            code: eap_code,
            id: eap_id,
            len: eap_len,
            typ: eap_type,
            cont: eap_cont,
        })
    }

    fn write_to_data(&self, data: &mut BytesMut) {
        data.put_u8(self.code);
        data.put_u8(self.id);
        data.put_u16(self.len);
        data.put_u8(self.typ);
        if let Some(eap_cont) = &self.cont {
            eap_cont.write_to_data(data);
        }
    }
}

impl EAPContext {
    pub fn new(device: Arc<Device>, config: &AuthConfig) -> Self {
        // let (tx, rx) = mpsc::channel::<Vec<u8>>();
        EAPContext {
            device,
            config: config.clone(),
        }
    }

    pub fn send_eapol_logoff(&self) -> io::Result<()> {
        let mut data = BytesMut::with_capacity(96);
        let eth_header = HeaderEth {
            dest_mac: QUERY_MAC,
            src_mac: self.device.mac,
            ver: 0x888e,
        };
        let _8021x_header = Header8021X {
            ver: 1,
            typ: 2,
            len: 0,
        };

        eth_header.write_to_data(&mut data);
        _8021x_header.write_to_data(&mut data);
        let l = data.len();
        data.put_bytes(0, 96 - l);

        // put_mac(&mut data, QUERY_MAC); // dest mac
        // put_mac(&mut data, self.device.mac); // src mac
        // data.put_u16(0x88_8e); // eth type
        // data.put_u8(0x01); // eapol ver
        // data.put_u8(0x02); // eapol type
        // assert_eq!(data.len(), 16);
        // data.put_bytes(0x00, 80); // add 80 0x00
        // assert_eq!(data.len(), 96);
        self.device.send(data.to_vec())?;
        Ok(())
    }

    pub fn send_eapol_start(&self) -> io::Result<()> {
        let mut data = BytesMut::with_capacity(96);
        let eth_header = HeaderEth {
            dest_mac: QUERY_MAC,
            src_mac: self.device.mac,
            ver: 0x888e,
        };
        let _8021x_header = Header8021X {
            ver: 1,
            typ: 1,
            len: 0,
        };

        eth_header.write_to_data(&mut data);
        _8021x_header.write_to_data(&mut data);
        let l = data.len();
        data.put_bytes(0, 96 - l);
        debug!("eapol start data: {:#x}", data);

        // put_mac(&mut data, QUERY_MAC); // dest mac
        // put_mac(&mut data, self.device.mac); // src mac
        // data.put_u16(0x88_8e); // eth type
        // data.put_u8(0x01); // eapol ver
        // data.put_u8(0x01); // eapol type
        // assert_eq!(data.len(), 16);
        // data.put_bytes(0x00, 80);
        // assert_eq!(data.len(), 96);
        self.device.send(data.to_vec())?;
        Ok(())
    }

    pub fn send_response_identity(&self, id: u8, remote_mac: MacAddr) -> io::Result<()> {
        let mut data = BytesMut::with_capacity(96);
        let eth_header = HeaderEth {
            dest_mac: remote_mac,
            src_mac: self.device.mac,
            ver: 0x888e,
        };
        let mut eap_identity = BytesMut::new();
        eap_identity.put_slice(self.config.username.as_bytes());
        let unknown_contents = hex!("00 44 61 00 00"); // TODO: what is the meaning?
        eap_identity.put_slice(&unknown_contents);
        eap_identity.put_slice(&self.config.auth_ip.octets());
        let eapol_len = eap_identity.len() as u16 + 5;
        let _8021x_header = Header8021X {
            ver: 1,
            typ: 0,
            len: eapol_len,
        };
        let eap_header = HeaderEAP {
            code: 2,
            id,
            len: eapol_len,
            typ: 1,
            cont: Some(EAPCont::Identity(eap_identity.to_vec())),
        };

        eth_header.write_to_data(&mut data);
        _8021x_header.write_to_data(&mut data);
        eap_header.write_to_data(&mut data);
        let l = data.len();
        data.put_bytes(0, 96 - l);

        // put_mac(&mut data, remote_mac); // dest mac
        // put_mac(&mut data, self.device.mac); // src mac
        // data.put_u16(0x88_8e); // eth type
        // data.put_u8(0x01); // eapol ver
        // data.put_u8(0x00); // eapol type

        // let mut eap_identity = BytesMut::new();
        // eap_identity.put_slice(self.config.username.as_bytes());
        // let unknown_contents = hex!("00 44 61 00 00"); // TODO: what is the meaning?
        // eap_identity.put_slice(&unknown_contents);
        // eap_identity.put_slice(&self.config.auth_ip.octets());
        // assert_eq!(eap_identity.len(), 21);

        // let eapol_len: u16 = eap_identity.len() as u16 + 5;
        // data.put_u16(eapol_len); // eapol.len

        // // 5 bytes, that's why eapol_len should add 5
        // data.put_u8(0x02); // response(2)
        // data.put_u8(0x01); // id: 1
        // data.put_u16(eapol_len); // eap.len
        // data.put_u8(0x01); // type: identity(1)
        // data.put(eap_identity);
        // assert_eq!(data.len(), 44);
        // data.put_bytes(0x00, 52); // 96 - 44 = 52
        // assert_eq!(data.len(), 96);
        debug!("response identity data: {:#x}", data);
        self.device.send(data.to_vec())?;
        Ok(())
    }

    pub fn send_response_md5_challenge(
        &self,
        id: u8,
        remote_mac: MacAddr,
        md5_value: Vec<u8>,
    ) -> io::Result<()> {
        let mut data = BytesMut::with_capacity(96);
        let eth_header = HeaderEth {
            dest_mac: remote_mac,
            src_mac: self.device.mac,
            ver: 0x888e,
        };
        let mut plain_text = BytesMut::new();
        plain_text.put_u8(0x00); // eap.id (seems only 0x00)
        plain_text.put_slice(self.config.password.as_bytes());
        plain_text.put_slice(&md5_value);
        let digest = md5::compute(plain_text);
        assert_eq!(digest.len(), 16);

        let mut md5_extra = BytesMut::new();
        md5_extra.put_slice(self.config.username.as_bytes());
        let unknown_contents = hex!("00 44 61 00 00"); // TODO: what is the meaning?
        md5_extra.put_slice(&unknown_contents);
        md5_extra.put_slice(&self.config.auth_ip.octets());
        assert_eq!(md5_extra.len(), 21);
        let eapol_len = (digest.len() + md5_extra.len() + 6) as u16;

        let _8021x_header = Header8021X {
            ver: 1,
            typ: 0,
            len: eapol_len,
        };
        let eap_header = HeaderEAP {
            code: 2,
            id,
            len: eapol_len,
            typ: 4,
            cont: Some(EAPCont::MD5Challenge {
                value_size: digest.len() as u8,
                md5_value: digest.to_vec(),
                extra_data: md5_extra.to_vec(),
            }),
        };

        eth_header.write_to_data(&mut data);
        _8021x_header.write_to_data(&mut data);
        eap_header.write_to_data(&mut data);
        let l = data.len();
        data.put_bytes(0, 96 - l);

        self.device.send(data.to_vec())?;
        Ok(())
    }

    pub fn receive_data(&self) -> Option<EAPStatus> {
        let data = match self.device.receive() {
            Ok(data) => data,
            Err(_) => panic!("device receive error"),
        };
        if data.len() != 64 && data.len() != 96 {
            return None;
        }
        let data = Bytes::copy_from_slice(&data);
        let eth_header = HeaderEth::from_data(&data)?;
        let _8021x_header = Header8021X::from_data(&data)?;
        let eap_header = HeaderEAP::from_data(&data)?;
        let eap_code = eap_header.code;
        let eap_type = eap_header.typ;
        match eap_code {
            3 => {
                // success
                Some(EAPStatus::Success)
            }
            1 => {
                // request
                match eap_type {
                    1 => {
                        // request identity
                        Some(EAPStatus::RequestIdentity {
                            id: eap_header.id,
                            remote_mac: eth_header.src_mac,
                        })
                    }
                    4 => {
                        // request md5 challenge
                        if let Some(EAPCont::MD5Challenge { md5_value, .. }) = eap_header.cont {
                            Some(EAPStatus::RequestMD5Challenge {
                                id: eap_header.id,
                                md5_value,
                            })
                        } else {
                            None
                        }
                    }
                    _ => {
                        error!("unknown eap type: {}", eap_type);
                        None
                    }
                }
            }
            4 => Some(EAPStatus::Failure),
            _ => {
                error!("unknown eap code: {}", eap_code);
                None
            }
        }

        // let dest_mac = &data[0..6];
        // let mut src_mac: [u8; 6] = Default::default();
        // src_mac.copy_from_slice(&data[6..12]);
        // let eth_type = &data[12..14];
        // let eapol_ver = data[14];
        // let eapol_type = data[15];
        // let eapol_len = &data[16..18];
        // let eap_code = data[18];
        // let eap_id = data[19];
        // let eap_len = &data[20..22];
        // let eap_type = data[22];

        // match eap_code {
        //     0x03 => {
        //         debug!("eap code: success");
        //         let eap_len = &data[20..22];
        //         let checksum = &data[60..64];
        //         Some(EAPStatus::Success)
        //     }
        //     0x01 => {
        //         debug!("eap code: request");
        //         match eap_type {
        //             0x01 => {
        //                 // get request identity
        //                 let checksum = &data[60..64];
        //                 let remote_mac = MacAddr::from(src_mac);
        //                 // self.send_response_identity(remote_mac).unwrap();
        //                 Some(EAPStatus::RequestIdentity(remote_mac))
        //             }
        //             0x04 => {
        //                 // get request md5 challenge
        //                 let md5_value_size = data[23];
        //                 assert_eq!(md5_value_size, 16);
        //                 let md5_value = &data[24..40];
        //                 let md5_extra_data = &data[40..44];
        //                 let checksum = &data[60..64];
        //                 // self.send_response_md5_challenge(md5_value).unwrap();
        //                 Some(EAPStatus::RequestMD5Challenge(md5_value.to_vec()))
        //             }
        //             _ => todo!("unknown eap code: {}", eap_code),
        //         }
        //     }
        //     _ => {
        //         // including 0x02: response
        //         debug!("unexpected eap code: {}", eap_code);
        //         None
        //     }
        // }
    }

    pub fn receive_data_until(&self) -> EAPStatus {
        let mut cnt = 0;
        loop {
            if let Some(eap_status) = self.receive_data() {
                return eap_status;
            } else {
                cnt += 1;
                // debug!("cnt: {}", cnt);
            }
            if cnt == 500 {
                panic!("cnt >= 500");
            }
        }
    }
}
