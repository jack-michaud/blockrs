use blockrs::crypt;
use blockrs::block::{MiningError, Blockchain};

fn run() -> Result<(), MiningError> {
    let mut chain = Blockchain::new()?;
    let (private, public) = crypt::generate_keys();
    let shared_secret = crypt::generate_shared_secret(&private, &chain.first().unwrap().headers.public_key);

    println!("Adding data to chain..."); 
    chain.add_block_calculate(public, crypt::encrypt(&mut "This is data on the blockchain!".as_bytes().to_vec(), &shared_secret))?;
    chain.traverse();
    Ok(())
}
fn main() {
    run().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
    })
}
