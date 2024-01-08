use crate::sectors;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

pub struct Session {
    pub connection: Option<TcpStream>,
}

impl Session {
    fn new(connection: Option<TcpStream>) -> Self {
        Session { connection }
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut dat_len = [0; 8];
        match self.connection.as_mut().unwrap().read_exact(&mut dat_len) {
            Ok(_) => {
                let int_len = sectors::bytes_to_int(&dat_len);
                if int_len > 65535 || int_len == 0 {
                    return vec![];
                }
                let mut full_pkg = vec![0; int_len as usize];
                match self.connection.as_mut().unwrap().read_exact(&mut full_pkg) {
                    Ok(_) => full_pkg,
                    Err(err) => {
                        dbg!("Client Disconnected", err);
                        self.shutdown();
                        vec![]
                    }
                }
            }
            Err(err) => {
                dbg!("Client disconnected", err);
                self.shutdown();
                vec![]
            }
        }
    }

    pub fn send(&mut self, data: &[u8]) {
        let data = sectors::write_sector(data);
        self.connection.as_mut().unwrap().write_all(&data).unwrap();
    }

    pub fn shutdown(&mut self) {
        self.connection
            .as_mut()
            .unwrap()
            .shutdown(std::net::Shutdown::Both)
            .unwrap()
    }
}

pub fn connect(ip: String, port: u16) -> Session {
    let remote_addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
    let stream = TcpStream::connect(remote_addr).unwrap();
    Session::new(Some(stream))
}
