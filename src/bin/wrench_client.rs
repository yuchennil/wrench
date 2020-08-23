use std::io::{prelude::*, stdin};
use std::net::{Shutdown, TcpStream};

use wrench::{
    Client, Plaintext,
    Request::{self, *},
    Response, UserId,
};

const SERVER_URL: &str = "127.0.0.1:39656";

fn main() -> std::io::Result<()> {
    let mut client = Client::new().unwrap();
    call_server(AddPrekeys(client.id(), client.publish_prekeys()))?;
    print_usage(&client)?;

    let mut peer_id = None;
    loop {
        let mail = call_server(GetMail(client.id()))?.mail().unwrap();
        for envelope in mail {
            let (user_id, plaintext) = client.receive(envelope).unwrap();
            peer_id = Some(user_id.clone());
            print!(
                "{}: {}",
                serde_json::to_string(&client.id())?,
                std::str::from_utf8(&plaintext.0).unwrap(),
            );
        }
        let line = read_line()?;
        match (line.chars().next(), &peer_id) {
            (Some('/'), _) => {
                let user_id: UserId = serde_json::from_str(&line[1..])?;
                peer_id = Some(user_id.clone());
                if !client.has_session(&user_id) {
                    let prekey = call_server(GetPrekey(user_id))?.prekey().unwrap();
                    client.initiate(prekey).unwrap();
                }
            }
            (_, Some(user_id)) => {
                let plaintext = Plaintext(line.as_bytes().to_vec());
                call_server(AddMail(client.send(user_id.clone(), plaintext).unwrap()))?;
            }
            (_, None) => {
                println!("  error: no user_id specified");
                print_usage(&client)?;
                continue;
            }
        }
    }
}

fn read_line() -> std::io::Result<String> {
    let mut buffer = String::new();
    stdin().read_line(&mut buffer)?;
    Ok(buffer)
}

fn call_server(request: Request) -> std::io::Result<Response> {
    let mut stream = TcpStream::connect(SERVER_URL)?;
    let buffer = serde_json::to_vec(&request)?;
    stream.write_all(&buffer)?;
    stream.shutdown(Shutdown::Write)?;
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?;
    let response = serde_json::from_slice(&buffer)?;

    Ok(response)
}

fn print_usage(client: &Client) -> std::io::Result<()> {
    println!("  usage:");
    println!("    /<user_id>  switch chat to this user_id");
    println!("    <message>   send message to the current user_id");
    println!("  your user_id:");
    println!("{}", serde_json::to_string(&client.id())?);
    Ok(())
}
