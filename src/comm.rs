use serde::{Serialize, Deserialize};
use bincode;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use crate::block;

pub const BLOCK_REQUEST_SIZE: usize = 88;
pub const BLOCK_ACK_SIZE: usize = 12;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct BlockRequest {
    pub headers: block::BlockHeaders
}

impl<'a> PeerCommand<'a> for BlockRequest {
    fn get_size() -> usize {
        return BLOCK_REQUEST_SIZE;
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum BlockAck {
    Go(usize),
    NoGo
}
impl<'a> PeerCommand<'a> for BlockAck {
    fn get_size() -> usize {
        return BLOCK_ACK_SIZE;
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum PeerAction {
    /// Request to add a new calculated block to the blockchain
    BlockRequest,
    /// Request to share a recv'd block with a peer
    BlockShare
}
impl<'a> PeerCommand<'a> for PeerAction {
    fn get_size() -> usize {
        return 4;
    }
}


pub enum BlockRequestError {
    SerializeError,
    DeserializeError,
}

pub trait PeerCommand<'a>: Serialize + Deserialize<'a> {
    /// Gets max size of the command
    fn get_size() -> usize;
}

#[derive(Debug)]
pub enum PeerError {
    /// Ended connection
    EOF,
    /// Error reading message
    ReadStream,
    /// Error sending message
    WriteStream,
    SerializeError,
    DeserializeError,
    /// Invalid Data; bad size
    InvalidData,
}

pub struct Peer {
    pub stream: TcpStream
}

impl Peer {
    pub async fn recv<'a, T: PeerCommand<'a>>(&mut self, buf: &'a mut Vec<u8>) -> Result<T, PeerError> {
        buf.resize(T::get_size(), 0);
        let n = self.stream.read(buf.as_mut_slice()).await
            .map_err(|_| PeerError::ReadStream)?;

        if n == 0 {
            return Err(PeerError::EOF);
        }

        bincode::deserialize::<T>(buf.as_slice())
            .map_err(|_| PeerError::DeserializeError)
    }

    pub async fn send<'a, T: PeerCommand<'a>>(&mut self, val: &T) -> Result<(), PeerError> {
        let ack = bincode::serialize(val).map_err(|_| PeerError::SerializeError)?;
        self.write_all(&ack.to_vec()).await
    }

    pub async fn raw_read(&mut self, mut buf: &mut Vec<u8>) -> Result<usize, PeerError> {
        self.stream.read_buf(&mut buf).await.map_err(|_| PeerError::ReadStream)
    }

    pub async fn write_all(&mut self, buf: &Vec<u8>) -> Result<(), PeerError> {
        self.stream.write_all(&mut buf.as_slice()).await.map_err(|_| PeerError::WriteStream)?;
        Ok(())
    }
}

pub async fn handle_recv_block(peer: &mut Peer) -> Result<block::Block, PeerError> {
    loop {
        let mut req_buf = Vec::new();
        let block_request = peer.recv::<BlockRequest>(&mut req_buf).await?;
        println!("Got blockchain block request from: {:?}", block_request.headers.public_key);
        let size = block_request.headers.size;
        println!("Ready to accept {} bytes", size);
        peer.send(&BlockAck::Go(size)).await.map_err(|e| {
            match e {
                PeerError::SerializeError => eprintln!("Could not serialize Ack"),
                PeerError::WriteStream => eprintln!("Could not send Ack"),
                _ => {}
            };
            e
        })?;

        // Read data from peer
        let mut data_buf = Vec::<u8>::with_capacity(size);
        let n = peer.raw_read(&mut data_buf).await?;
        if n != size {
            println!("{:?}", data_buf);
            return Err(PeerError::InvalidData);
        }
        println!("Read {} data bytes :)", n);
        return Ok(block::Block {
            headers: block_request.headers,
            data: data_buf
        })
    }
}

#[derive(Debug)]
pub enum BlockchainShareError {
    EOF
}

pub async fn handle_share_blockchain_with_peer(
    blockchain: &block::Blockchain, 
    peer: &mut Peer
) -> Result<(), PeerError> {
    peer.write_all(
        &bincode::serialize(&blockchain.blocks)
            .map_err(|_| PeerError::WriteStream)?).await
}

pub async fn handle_peer(blockchain: &block::Blockchain, mut peer: Peer) -> Result<(), PeerError> {
    loop {
        let mut action_buf = Vec::<u8>::new();
        match peer.recv::<PeerAction>(&mut action_buf).await? {
            PeerAction::BlockRequest => {
                println!("BlockRequest");
                handle_recv_block(&mut peer).await?;
            },
            PeerAction::BlockShare => {
                println!("BlockShare");
                handle_share_blockchain_with_peer(blockchain, &mut peer).await?;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::crypt;


    #[test]
    fn block_request_size() {
        let size = bincode::serialized_size(&BlockRequest {
            headers: block::BlockHeaders {
                nonce: 0,
                prev_block_hash: block::Sha256Hash::default(),
                public_key: crypt::PublicKey::from([0 as u8; 32]),
                size: 123,
                timestamp: 123
            }
        }).unwrap();
        assert_eq!(size as usize, BLOCK_REQUEST_SIZE);

        assert_eq!(BlockRequest::get_size(), BLOCK_REQUEST_SIZE);
    }

    #[test]
    fn blockack_size() {
        let size = bincode::serialized_size(&BlockAck::Go(8)).unwrap();
        assert_eq!(size as usize, BLOCK_ACK_SIZE);
        let size = bincode::serialized_size(&BlockAck::NoGo).unwrap();
        assert!((size as usize) < BLOCK_ACK_SIZE);

        assert_eq!(BlockAck::get_size(), BLOCK_ACK_SIZE);
    }

    #[test]
    fn peeraction_size() {
        let size = bincode::serialized_size(&PeerAction::BlockRequest).unwrap();
        assert_eq!(size as usize, PeerAction::get_size());
    }
}
