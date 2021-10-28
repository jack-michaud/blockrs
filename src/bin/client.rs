use blockrs::comm::{self, BLOCK_REQUEST_SIZE};
use std::sync::Arc;
use tokio::sync::{Mutex};
use tokio::net::{TcpListener};

#[derive(Debug)]
enum ClientError {
    CouldNotBind,
    CouldNotAcceptListener
}


async fn run() -> Result<(), ClientError> {
    let blockchain = Arc::new(Mutex::new(blockrs::block::Blockchain::new().unwrap()));
    let mut listener = TcpListener::bind(
        "127.0.0.1:6137").await
        .map_err(|_| ClientError::CouldNotBind)?;
    loop {
        let (sock, _) = listener.accept().await.map_err(|_| ClientError::CouldNotAcceptListener)?;
        let mut peer = comm::Peer {
            stream: sock
        };
        let blockchain = blockchain.clone();
        tokio::spawn(async move {
            let blockchain = blockchain.clone();
            match comm::handle_recv_block(&mut peer).await {
                Ok(block) => {
                    let mut blockchain = blockchain.lock_owned().await;
                    // TODO verify that the block has the correct parent
                    blockchain.add_block(block);
                    blockchain.traverse();
                },
                Err(err) => {
                    eprintln!("Could not receive block: {:?}", err);
                }
            }
            
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    run().await.map_err(|err| {
        eprintln!("Got err: {:?}", err);
    });
}
