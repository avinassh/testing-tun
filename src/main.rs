use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;

extern crate byteorder;
extern crate etherparse;
extern crate tun;

const TUN_PCK_INFO_LEN: usize = 4;

fn main() {
    let mut config = tun::Configuration::default();
    config
        .name("utun5")
        .address((192, 168, 0, 10))
        .netmask((255, 255, 255, 0))
        .up();

    let mut nic = tun::create(&config).unwrap();
    let mut buf = [0u8; 1504];
    let mut packet_info = [0u8; 4];
    let mut responded = false;

    loop {
        let nbytes = nic.read(&mut buf).unwrap();
        packet_info = [buf[0], buf[1], buf[2], buf[3]];
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[TUN_PCK_INFO_LEN..nbytes]) {
            Ok(ip_header) => {
                let source_addr = ip_header.source_addr();
                let destination_addr = ip_header.destination_addr();
                let protocol = ip_header.protocol();
                eprintln!(
                    "{} → {} size={}b proto={:x} ttl={}",
                    source_addr,
                    destination_addr,
                    ip_header.payload_len(),
                    protocol,
                    ip_header.ttl(),
                );

                if protocol != 0x06 {
                    // not TCP
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[TUN_PCK_INFO_LEN + ip_header.slice().len()..],
                ) {
                    Ok(tcp_header) => {
                        let data_index =
                            TUN_PCK_INFO_LEN + ip_header.slice().len() + tcp_header.slice().len();
                        let data = &buf[data_index..nbytes];
                        eprintln!(
                            "{}:{} → {}:{} size={}b proto=tcp",
                            ip_header.source_addr(),
                            tcp_header.source_port(),
                            ip_header.destination_addr(),
                            tcp_header.destination_port(),
                            data.len(),
                        );
                        if responded {
                            // already responded,
                            continue
                        }

                        let mut buf = [0u8; 1500];
                        let mut syn_ack = etherparse::TcpHeader::new(
                            tcp_header.destination_port(),
                            tcp_header.source_port(),
                            0,
                            tcp_header.window_size(),
                        );
                        syn_ack.syn = true;
                        syn_ack.ack = true;
                        syn_ack.acknowledgment_number = tcp_header.sequence_number() + 1;
                        let mut reply_ip_payoad = etherparse::Ipv4Header::new(
                            syn_ack.header_len(),
                            64,
                            etherparse::IpTrafficClass::Tcp,
                            [
                                ip_header.destination()[0],
                                ip_header.destination()[1],
                                ip_header.destination()[2],
                                ip_header.destination()[3],
                            ],
                            [
                                ip_header.source()[0],
                                ip_header.source()[1],
                                ip_header.source()[2],
                                ip_header.source()[3],
                            ],
                        );
                        syn_ack.checksum = syn_ack
                            .calc_checksum_ipv4(&reply_ip_payoad, &[])
                            .unwrap();
                        let unwritten: usize = {
                            let mut unwritten = &mut buf[..];
                            unwritten.write_all(&packet_info);
                            reply_ip_payoad.write(&mut unwritten).unwrap();
                            syn_ack.write(&mut unwritten).unwrap();
                            unwritten.len()
                        };
                        eprintln!(
                            "writing({}) {:?}",
                            buf.len() - unwritten,
                            &buf[..buf.len() - unwritten]
                        );
                        nic.write(&buf[..buf.len() - unwritten]).unwrap();
                        responded = true;
                    }
                    Err(e) => {
                        eprintln!("a bad TCP packet: {:?}", e)
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring packet cos {:?}", e)
            }
        }
    }
}
