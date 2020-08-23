use std::io::prelude::*;
use std::net::{Shutdown, TcpListener};

use wrench::Server;

const SERVER_URL: &str = "127.0.0.1:39656";

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(SERVER_URL)?;
    let mut server = Server::new();
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer)?;
        let request = serde_json::from_slice(&buffer)?;
        println!("{:?}", request);
        let response = server.handle(request);
        let buffer = serde_json::to_vec(&response)?;
        stream.write_all(&buffer)?;
        stream.shutdown(Shutdown::Write)?;
    }
    Ok(())
}
