use std::io::Read;
use std::io::Write;

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
    let mut responded = false;

    loop {
        let nbytes = nic.read(&mut buf).unwrap();
        let packet_info:[u8; 4] = [buf[0], buf[1], buf[2], buf[3]];
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[TUN_PCK_INFO_LEN..nbytes]) {
            Ok(ip_header) => {
                if ip_header.protocol() != 0x06 { // 0x06 is TCP
                    // not TCP
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[TUN_PCK_INFO_LEN + ip_header.slice().len()..],
                ) {
                    Ok(tcp_header) => {
                        eprintln!(
                            "{}:{} → {}:{} ip_size={}b tcp_size=0b proto=tcp ttl={}",
                            ip_header.source_addr(),
                            tcp_header.source_port(),
                            ip_header.destination_addr(),
                            tcp_header.destination_port(),
                            ip_header.payload_len(),
                            ip_header.ttl()
                        );
                        if responded {
                            // already responded,
                            continue
                        }

                        let mut buf = [0u8; 1500];
                        let mut syn_ack_payload = etherparse::TcpHeader::new(
                            tcp_header.destination_port(),
                            tcp_header.source_port(),
                            0,
                            tcp_header.window_size(),
                        );
                        syn_ack_payload.syn = true;
                        syn_ack_payload.ack = true;
                        syn_ack_payload.acknowledgment_number = tcp_header.sequence_number() + 1;
                        let ip_payload = etherparse::Ipv4Header::new(
                            syn_ack_payload.header_len(),
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
                        syn_ack_payload.checksum = syn_ack_payload
                            .calc_checksum_ipv4(&ip_payload, &[])
                            .unwrap();
                        let unwritten: usize = {
                            let mut unwritten = &mut buf[..];
                            unwritten.write_all(&packet_info).unwrap();
                            ip_payload.write(&mut unwritten).unwrap();
                            syn_ack_payload.write(&mut unwritten).unwrap();
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
