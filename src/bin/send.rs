use tokio::net::TcpStream;
use tokio::prelude::*;

use blockrs::block::{Block, Sha256Hash};
use blockrs::crypt::{generate_keys};
use blockrs::comm::{self, BlockRequest, BlockAck, BLOCK_ACK_SIZE};

#[derive(Debug)]
enum ClientError {
    CouldNotConnect,
    CouldNotSendBlock,
    CouldNotRecvAck,
    CouldNotSendData
}

async fn run() -> Result<(), ClientError> {
    let stream = TcpStream::connect("localhost:6137").await.map_err(|_| ClientError::CouldNotConnect)?;
    let mut peer = comm::Peer {
        stream
    };

    let (secret, public) = generate_keys();

    let block = Block::new(public, "Test".as_bytes().to_vec(), Sha256Hash::default()).ok().unwrap();
    println!("Got block: {:?}", block);
    let size = block.headers.size.clone();
    peer.send(&BlockRequest {
        headers: block.headers
    }).await.map_err(|_| ClientError::CouldNotSendBlock)?;
    println!("Sent! Waiting for ack...");
    let mut ack_buf = Vec::<u8>::new();
    match peer.recv::<BlockAck>(&mut ack_buf).await
        .map_err(|_| ClientError::CouldNotRecvAck)? {
        BlockAck::Go(acked_size) => {
            assert_eq!(acked_size, size);
            println!("Confirmed to send {} data bytes", size);
            peer.write_all(&block.data).await
                .map_err(|_| ClientError::CouldNotSendData)?;
            println!("Sent!");
        },
        BlockAck::NoGo => {
            println!("No send");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    run().await.map_err(|err| {
        eprintln!("Got err: {:?}", err);
    });
}
