#[macro_use]
extern crate log;

use env_logger::Builder;
use log::LevelFilter;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{Read, Write};

mod aes_func;
mod sectors;
mod session_level;
use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes256;
use generic_array::typenum::U32;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[macro_export]
macro_rules! hashmap {
    ( $key_type:ty; $value_type:ty ) => {
        HashMap::<$key_type, $value_type>::new()
    };
    ( $( $key:expr => $value:expr ),+ $(,)? ) => {
        {
            let mut hashmap = HashMap::new();
            $( hashmap.insert($key, $value); )*
            hashmap
        }
    };
}

struct User {
    session: session_level::Session,
    username: String,
    password: String,
    datadir: String,
    sector_num: i128,
    keys: (RsaPublicKey, RsaPrivateKey),
    session_key: Option<Aes256>,
    chats: sectors::SectorsType
}

impl User {
    pub fn new(ip: String, username: String, password: String, dir: String) -> Self {
        let sector_num = -1;
        if !fs::metadata(&dir).is_ok() {
            fs::create_dir(&dir).expect("Failed to create directory");
        }
        let datadir = format!("{}/{}", dir, &username.trim());
        if !fs::metadata(&datadir).is_ok() {
            fs::create_dir(&datadir).expect("Failed to create directory");
        }
        let usr = format!("{}/{}", &datadir, username.trim());
        if !fs::metadata(&usr).is_ok() {
            info!("[!] Generating a session...");
            let mut file = File::create(&usr).expect("Failed to create file");
            let data = aes_func::gen_session(&password);
            file.write_all(&data).expect("Failed to write to file");
        }
        let mut enc_keypair = Vec::new();
        let mut usrfile = File::open(usr).unwrap();
        usrfile.read_to_end(&mut enc_keypair).unwrap();
        let key: Aes256 = Aes256::new(GenericArray::from_slice(&aes_func::get_aes_session_password(password.trim().as_bytes())));
        let keys = aes_func::get_session(enc_keypair, &key);
        let mut chats = sectors::SectorsType::new(Some(format!("{datadir}/chats.txt")), Some(key));
        chats.load().unwrap();
        let session = session_level::connect(ip.trim().to_string(), 4444);
        Self {
            session,
            username,
            password,
            datadir,
            sector_num,
            keys,
            session_key: None,
            chats
        }
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut data = self.session.recv();
        while data.is_empty() {
            data = self.session.recv();
        }
        if let Some(session_key) = &self.session_key {
            data = aes_func::decrypt(session_key, data);
        }
        data.to_vec()
    }

    pub fn send(&mut self, mut data: Vec<u8>) {
        if let Some(session_key) = &self.session_key {
            data = aes_func::encrypt(session_key, &data);
        }

        self.session.send(&data);
    }

    pub fn sendarr(&mut self, data: Vec<Vec<&[u8]>>) {
        let data = sectors::write_sectors(data);
        self.send(data);
    }

    pub fn auth(&mut self) -> Vec<u8> {
        let public_key_pem = self.keys.0.to_public_key_pem(LineEnding::LF).unwrap();
        let username = self.username.to_owned();
        let data = vec![
            vec![public_key_pem.as_bytes()],
            vec![username.trim().as_bytes()],
        ];
        self.sendarr(data);
        let encrypted_session_key = self.recv();
        let session_key = self
            .keys
            .1
            .decrypt(Pkcs1v15Encrypt, &encrypted_session_key)
            .unwrap();
        self.session_key = Some(Aes256::new(GenericArray::<u8, U32>::from_slice(
            &session_key,
        )));
        self.recv()
    }

    pub fn mkchat(&mut self, chatname: &str, password: &str) -> Vec<u8> {
        self.sendarr(vec![vec![b"0"], vec![chatname.as_bytes()], vec![&aes_func::gen_chathash(password.as_bytes())]]);
        let code = self.recv();
        if code == vec![0] {
            self.join_chat(chatname, password);
        }
        code
    }

    pub fn join_chat(&mut self, chatname: &str, password: &str) -> Vec<u8> {
        self.sendarr(vec![vec![b"1"], vec![chatname.as_bytes()], vec![&aes_func::gen_chathash(password.as_bytes())]]);
        let code = self.recv();
        if code == vec![0] {
            self.chats.add(vec![vec![chatname.as_bytes()], vec![&aes_func::gen_chathash(password.as_bytes())]]);
            self.chats.save().unwrap();
        }
        else if code == vec![3] {
            if self.chats.findbin(0, chatname.as_bytes()) == -1 {
                self.chats.add(vec![vec![chatname.as_bytes()], vec![&aes_func::gen_chathash(password.as_bytes())]]);
                self.chats.save().unwrap();
            }
        }
        code
    }

    pub fn getchats(&mut self, field_num: usize) -> Vec<Vec<u8>> {
        self.chats.fields(field_num)
    }

    fn checkcode(&self, code: &Vec<u8>) -> bool {
        code.to_vec() == vec![0u8; 1]
    }

    pub fn decode(&self, func: &str, code: Vec<u8>) -> (&str, &str) {
        let code_table = hashmap! {
            "auth" => hashmap! {
                vec![0] => ("0", "Authenticated"),
                vec![1] => ("1", "This username is taken. Try to change it")
            },
            "mkchat" => hashmap! {
                vec![0] => ("0", "Chat created"),
                vec![1] => ("1", "This chatname is taken. Try to change it")
            },
            "join_chat" => hashmap! {
                vec![0] => ("0", "Joined the chat"),
                vec![1] => ("1", "Chat not found"),
                vec![2] => ("2", "Bad chat hash"),
                vec![3] => ("3", "You are already in chat")
            }
        };
        return *code_table.get(func).and_then(|c| c.get(&code)).unwrap();
    }
}

fn main() {
    Builder::new().filter_level(LevelFilter::max()).init();
    let mut ip = String::new();
    let mut username = String::new();
    let mut password = String::new();
    print!("Enter server ip: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ip).unwrap();
    print!("Enter your username: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut username).unwrap();
    print!("Enter your password: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut password).unwrap();
    let prompt = format!("{}@{} ~> ", username.trim(), ip.trim());
    let mut client = User::new(ip, username, password, "data".to_string());
    let code = client.auth();
    if code != vec![0] {
        error!("{}", client.decode("auth", code).1);
    } else {
        info!("{}", client.decode("auth", code).1);
    }
    loop {
        let mut cmdraw = String::new();
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut cmdraw).unwrap();
        let cmd: Vec<&str> = cmdraw.trim().split_whitespace().collect();
        if !cmd.is_empty() && cmd.len() > 0 {
            let cmd_name = cmd[0];
            let cmd_args = &cmd[1..];
            match cmd_name {
                "help" => {
                    info!("stub");
                }

                "chats" => {
                    info!("Ok. Here are your chats.");
                    for (index, chatname) in client.getchats(0).iter().enumerate() {
                        info!("[{}] - {}", index, sectors::bytes_to_utf8(chatname.to_vec()));
                    }
                }
                "mkchat" => {
                    if cmd.len() < 3 {
                        warn!("Not enough args");
                    } else {
                        let code = client.mkchat(cmd_args[0], cmd_args[1]);
                        if code != vec![0] {
                            error!("{:?}", client.decode("mkchat", code).1);
                        } else {
                            info!("{:?}", client.decode("mkchat", code).1);
                        }
                    }
                }

                "join" => {
                    if cmd.len() < 3 {
                        warn!("Not enough args");
                    } else {
                        let code = client.join_chat(cmd_args[0], cmd_args[1]);
                        if code != vec![0] {
                            error!("{:?}", client.decode("join_chat", code).1);
                        } else {
                            info!("{:?}", client.decode("join_chat", code).1);
                        }
                    }
                }

                _ => {
                    warn!("Unknown command: {:?}", cmd_name);
                }
            }
        }
    }
}
