use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use rsa::{
    pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, pkcs8::EncodePrivateKey,
    pkcs8::EncodePublicKey, pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey,
};

use flate2::write::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

use generic_array::typenum::U32;
use sha2::{Digest, Sha256};

use crate::sectors;

pub fn pkcs7padding(data: Vec<u8>, block_length: usize) -> Vec<u8> {
    let padding_size = block_length - (data.len() % block_length);
    let mut padded_data = data.to_vec();
    padded_data.extend(vec![padding_size as u8; padding_size]);
    padded_data
}

pub fn pkcs7unpadding(data: Vec<u8>) -> Vec<u8> {
    let data_len = data.len();
    let padding_length = data[data_len - 1] as usize;
    data[0..data_len - padding_length].to_vec()
}

pub fn encrypt(_aes: &Aes256, data: &Vec<u8>) -> Vec<u8> {
    let mut encrypted: Vec<u8> = Vec::new();
    let data = pkcs7padding(data.to_vec(), 16);
    for chunk in data.chunks_exact(16) {
        let block = GenericArray::from_slice(chunk);
        let mut mut_block = block.clone();
        _aes.encrypt_block(&mut mut_block);
        encrypted.extend_from_slice(mut_block.as_slice());
    }
    encrypted
}

pub fn decrypt(_aes: &Aes256, data: Vec<u8>) -> Vec<u8> {
    let mut decrypted: Vec<u8> = Vec::new();
    for chunk in data.chunks_exact(16) {
        let block = GenericArray::clone_from_slice(chunk);
        let mut mut_block = block.clone();
        _aes.decrypt_block(&mut mut_block);
        decrypted.extend_from_slice(mut_block.as_slice());
    }
    pkcs7unpadding(decrypted)
}

pub fn packethash(packet: &[u8]) -> u64 {
    let sum: u64 = packet.iter().map(|byte| *byte as u64).sum();
    let pkg_len: u64 = packet.len() as u64;
    sum/pkg_len
}

pub fn gen_chathash(key: &[u8]) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(sectors::int_to_bytes(packethash(key)));
    hasher.update(b"salt");
    let result = hasher.finalize();
    result
}

pub fn get_aes_session_password(key: &[u8]) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(sectors::int_to_bytes(packethash(key)));
    hasher.update(b"salt");
    let result = hasher.finalize();
    result
}

pub fn get_session(data: Vec<u8>, key: &Aes256) -> (RsaPublicKey, RsaPrivateKey) {
    let mut decompressor = ZlibDecoder::new(Vec::new());
    let decrypted_keys = decrypt(key, data);
    decompressor
        .write_all(&decrypted_keys)
        .expect("\n\t\t\t\t!!!WRONG PASSWORD!!!\n\n\n");
    let keys = sectors::read_sectors(decompressor.finish().unwrap());
    (
        RsaPublicKey::from_public_key_pem(&keys[0]).unwrap(),
        RsaPrivateKey::from_pkcs8_pem(&keys[1]).unwrap(),
    )
}

pub fn gen_session(password: &String) -> Vec<u8> {
    let mut compressor = ZlibEncoder::new(Vec::new(), Compression::default());
    let aes_key = Aes256::new(GenericArray::from_slice(&get_aes_session_password(
        password.trim().as_bytes(),
    )));
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let pub_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
    let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    dbg!("{:?}", &pub_pem);
    dbg!("{:?}", &priv_pem);
    let merged_keys =
        sectors::write_sectors(vec![vec![pub_pem.as_bytes()], vec![priv_pem.as_bytes()]]);
    compressor.write_all(&merged_keys).unwrap();
    let data_session = compressor.finish().unwrap();
    encrypt(&aes_key, &data_session)
}
