use aes::Aes256;

use memmem::{Searcher, TwoWaySearcher};

use flate2::write::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::convert::TryInto;

use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;

use crate::aes_func;

pub struct SectorsType {
    pub data: Vec<u8>,
    pub filename: Option<String>,
    key: Option<Aes256>,
}

pub fn int_to_bytes(int_: u64) -> Vec<u8> {
    if int_ == 0 {
        return vec![0];
    }
    int_.to_le_bytes().to_vec()
}

pub fn bytes_to_int(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("Found invalid UTF-8")
}

pub fn write_sector(data: &[u8]) -> Vec<u8> {
    let data_length = int_to_bytes(data.len() as u64);
    [data_length, data.to_vec()].concat()
}

pub fn write_sectors(data: Vec<Vec<&[u8]>>) -> Vec<u8> {
    let mut all_data = Vec::new();
    for part_data in data {
        for bytes in part_data {
            all_data.extend(write_sector(&bytes));
        }
    }
    all_data
}

pub fn reader(data: Vec<u8>) -> impl Iterator<Item = (i8, Vec<u8>)> {
    let mut index = 0;
    let mut iter: i8 = -1;

    std::iter::from_fn(move || {
        if index < data.len() {
            let data_head = &data[index..index + 8];
            let data_head = bytes_to_int(data_head) as usize;

            index += 8;
            let part_data: &[u8] = &data[index..index + data_head as usize];

            index += data_head as usize;
            iter += 1;
            Some((iter, part_data.into()))
        } else {
            None
        }
    })
}

pub fn read_sectors(data: Vec<u8>) -> Vec<String> {
    let mut reader = reader(data);
    let mut sectors = Vec::new();

    while let Some((_iter, sector)) = reader.next() {
        sectors.push(bytes_to_utf8(sector));
    }

    sectors
}

pub fn read_sectors_b(data: Vec<u8>) -> Vec<Vec<u8>> {
    let mut reader = reader(data);
    let mut sectors = Vec::new();
    while let Some((_iter, sector)) = reader.next() {
        sectors.extend(vec![sector]);
    }

    sectors
}

impl SectorsType {
    pub fn new(filename: Option<String>, key: Option<Aes256>) -> Self {
        Self {
            data: Vec::new(),
            filename,
            key,
        }
    }

    pub fn add(&mut self, info: Vec<Vec<&[u8]>>) {
        let mut sector = write_sector(&write_sectors(info));
        self.data.append(&mut sector);
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        if let Some(filename) = &self.filename {
            let mut file = File::create(&filename)?;
            if let Some(_key) = &self.key {
                let key = self.key.as_ref().unwrap();
                let mut compressor = ZlibEncoder::new(Vec::new(), Compression::default());
                compressor.write_all(&self.data).unwrap();
                let compressed_data = compressor.finish().unwrap();
                let encrypted_data = aes_func::encrypt(&key, &compressed_data);
                file.write_all(&encrypted_data)?;
            } else {
                file.write_all(&self.data)?;
            }
        }

        Ok(())
    }

    pub fn load(&mut self) -> std::io::Result<()> {
        if let Some(ref filename) = self.filename {
            if let Err(_metadata) = fs::metadata(filename) {
                self.save().unwrap();
            }
        }
        if let Some(filename) = &self.filename {
            if let Some(_key) = &self.key {
                let key = self.key.as_ref().unwrap();
                let mut encrypted_data = Vec::new();
                File::open(filename)?.read_to_end(&mut encrypted_data)?;
                let decrypted_data = aes_func::decrypt(&key, encrypted_data);
                let mut decompressor = ZlibDecoder::new(Vec::new());
                decompressor.write_all(&decrypted_data)?;
                let decompressed_data = decompressor.finish()?;

                self.data = decompressed_data;
            } else {
                self.data.clear();
                File::open(filename)?.read_to_end(&mut self.data)?;
            }
        }

        Ok(())
    }

    pub fn find(&mut self, field_num: usize, query: &[u8]) -> i32 {
        let data = &self.data;
        let search = TwoWaySearcher::new(&query);

        for (en, sector) in reader(data.to_vec()) {
            if search.search_in(&sector).is_some() {
                let fields = read_sectors(sector.into());
                if fields.len() >= field_num + 1 {
                    if fields[field_num].as_bytes() == query {
                        return en as i32;
                    }
                }
            }
        }
        -1
    }

    pub fn findbin(&mut self, field_num: usize, query: &[u8]) -> i32 {
        let data = &self.data;
        let search = TwoWaySearcher::new(&query);

        for (en, sector) in reader(data.to_vec()) {
            if search.search_in(&sector).is_some() {
                let fields = read_sectors_b(sector.into());
                if fields.len() >= field_num + 1 {
                    if fields[field_num] == query {
                        return en as i32;
                    }
                }
            }
        }
        -1
    }

    pub fn getdat(&mut self, sector_num: u32, field_num: usize) -> Vec<u8> {
        let data = &self.data;
        for (en, sector) in reader(data.to_vec()) {
            if (en as u32) == sector_num {
                for (fen, fld) in reader(sector) {
                    if (fen as usize) == field_num {
                        return fld;
                    }
                }
            }
        }
        Vec::new()
    }

    pub fn rem(&mut self, sector_num: usize) {
        let data = &self.data;
        let mut sectors = read_sectors(data.to_vec());
        sectors.remove(sector_num);
        self.data = write_sectors(vec![sectors.iter().map(|sct| sct.as_bytes()).collect()]);
    }

    pub fn edit(&mut self, sector_num: u32, field_num: usize, data: Vec<u8>) {
        let selfdata = &self.data;
        let mut tmpdat = read_sectors_b(selfdata.to_vec());
        let tmpdat_trim = &tmpdat[sector_num as usize];
        let mut deser_data = read_sectors_b(tmpdat_trim.to_vec());

        if deser_data.len() - 1 >= field_num {
            deser_data[field_num] = data;
        } else {
            deser_data.push(data);
        }
        let ser_data = deser_data
            .iter()
            .map(|vec| vec![vec.as_slice()])
            .collect::<Vec<_>>();
        tmpdat[sector_num as usize] = write_sectors(ser_data);
        let serdat = tmpdat
            .iter()
            .map(|vec| vec![vec.as_slice()])
            .collect::<Vec<_>>();
        self.data = write_sectors(serdat);
    }

    pub fn add_to_field(&mut self, sector_num: u32, field_num: usize, data: Vec<u8>) {
        let mut new_data = self.getdat(sector_num, field_num);
        new_data.extend(data);
        self.edit(sector_num, field_num, new_data);
    }

    pub fn fields(&mut self, field_num: usize) -> Vec<Vec<u8>> {
        let selfdata = &self.data;
        let mut fields_vec: Vec<Vec<u8>> = Vec::new();
        for (_index, sector) in reader(selfdata.to_vec()) {
            let chatname = &read_sectors_b(sector)[field_num];
            fields_vec.push(chatname.to_vec());
        }
        fields_vec
    }

    pub fn obj_sec_get(&mut self, sector_num: u32, field_num: usize) -> SectorsType {
        let mut obj = SectorsType::new(None, None);
        obj.data = self.getdat(sector_num, field_num);
        obj
    }
}
