
use crate::crypt;

use std::error; 
use std::fmt;
use chrono::prelude::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

const DIFFICULTY: usize = 4;
const MAX_NONCE: u64 = 1_000_000;
const HASH_BYTE_SIZE: usize = 32;


fn get_target() -> BigUint {
    BigUint::one() << (256 - 4 * DIFFICULTY)
}

pub type Sha256Hash = [u8; HASH_BYTE_SIZE];

fn u64_into_u8_array(num: u64) -> [u8; 8] {
    return [
        num as u8,
        (num >> 8) as u8,
        (num >> 16) as u8,
        (num >> 24) as u8,
        (num >> 32) as u8,
        (num >> 40) as u8,
        (num >> 48) as u8,
        (num >> 56) as u8,
    ]
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockHeaders {
    pub timestamp: i64,
    pub prev_block_hash: Sha256Hash,
    pub nonce: u64,
    pub public_key: crypt::PublicKey,
    pub size: usize,
}

impl PartialEq for BlockHeaders {
    fn eq(&self, other: &Self) -> bool {
        return self.timestamp == other.timestamp &&
            self.prev_block_hash == other.prev_block_hash &&
            self.nonce == other.nonce &&
            self.public_key.to_bytes() == other.public_key.to_bytes() &&
            self.size == other.size;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    pub headers: BlockHeaders,
    // Body
    pub data: Vec<u8>
}



impl Block {
    pub fn genesis() -> Result<(Self, crypt::SecretKey), MiningError> {
        let (secret, public) = crypt::generate_keys();
        let shared_secret = crypt::generate_shared_secret(&secret, &public);
        let init_data = crypt::encrypt(&mut "gl2ncoin".as_bytes().to_vec(), &shared_secret);
        Self::new(public, init_data, Sha256Hash::default()).and_then(|g| {
            return Ok((g, secret))
        })
    }
    fn try_hash(&self) -> Option<u64> {
        let target = get_target();
        for nonce in 0..MAX_NONCE {
            let hash = self.calculate_hash(nonce);
            let hash_int = BigUint::from_bytes_be(&hash);
            if hash_int < target {
                return Some(nonce)
            }
        }
        None
    }
    fn calculate_hash(&self, nonce: u64) -> Sha256Hash {
        let mut headers = self.headers();
        headers.extend(&u64_into_u8_array(nonce));

        let mut hasher = Sha256::new();
        hasher.input(&headers);
        let mut hash = Sha256Hash::default();

        hasher.result(&mut hash);
        hash
    }
    pub fn hash(&self) -> Sha256Hash {
        self.calculate_hash(self.headers.nonce)
    }
    pub fn verify(&self) -> bool {
        let hash = self.calculate_hash(self.headers.nonce);
        let hash_int = BigUint::from_bytes_be(&hash);
        hash_int < get_target()
    }
    fn headers(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.headers.public_key.as_bytes());
        vec.extend(&u64_into_u8_array(self.headers.timestamp as u64));
        vec.extend(&self.headers.prev_block_hash);
        vec
    }
    pub fn new(public_key: crypt::PublicKey, data: Vec<u8>, prev_hash: Sha256Hash) -> Result<Self, MiningError> {
        let mut s = Self {
            data: data.to_owned().into(),
            headers: BlockHeaders {
                timestamp: Utc::now().timestamp(),
                prev_block_hash: prev_hash,
                nonce: 0,
                public_key,
                size: data.len()
            }
        };
        s.try_hash()
            .ok_or(MiningError::Iteration)
            .and_then(|nonce| {
                s.headers.nonce = nonce;
                Ok(s)
            })
    }
}

#[derive(Debug)]
pub enum MiningError {
    Iteration,
    NoParent
}

impl fmt::Display for MiningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MiningError::Iteration => write!(f, "could not mine block, hit iteration limit"),
            MiningError::NoParent => write!(f, "block has no parent"),
        }
    }
}

impl error::Error for MiningError {
    fn description(&self) -> &str {
        match *self {
            MiningError::Iteration => "could not mine block, hit iteration limit",
            MiningError::NoParent => "block has no parent"
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}


pub struct Blockchain {
    pub blocks: Vec<Block>,
    secret: crypt::SecretKey
}

impl Blockchain {
    pub fn new() -> Result<Self, MiningError> {
        let (genesis, secret) = Block::genesis()?;
        Ok(Self { blocks: vec![genesis], secret })
    }

    pub fn first(&self) -> Option<&Block> {
        self.blocks.first()
    }
    pub fn add_block(&mut self, block: Block) -> bool {
        if block.verify() {
            self.blocks.push(block);
            return true;
        }
        return false;
    }

    pub fn add_block_calculate(&mut self, public_key: crypt::PublicKey, data: Vec<u8>) -> Result<(), MiningError> {
        let block: Block;
        {
            match self.blocks.last() {
                Some(prev) => {
                    block = Block::new(public_key, data, prev.hash())?;
                },
                None => {
                    return Err(MiningError::NoParent)
                }
            }
        }
        self.blocks.push(block);
        Ok(())
    }

    pub fn traverse(&self) {
        for (i, block) in self.blocks.iter().enumerate() {
            println!("block: {}", i);
            println!("-> hash: {:?}", block.hash());
            println!("-> parent: {:?}", block.headers.prev_block_hash);
            println!("-> nonce: {:?}", block.headers.nonce);
            println!("-> public_key: {:?}", block.headers.public_key.as_bytes());
            let shared_secret = crypt::generate_shared_secret(&self.secret, &block.headers.public_key);
            let mut data_clone = block.data.clone();
            println!("-> data: {:?}", String::from_utf8(crypt::decrypt(&mut data_clone, &shared_secret).into()));
        }
    }
}

