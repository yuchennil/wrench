use std::io::{prelude::*, stdin};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc;
use std::{thread, time};

use wrench::{
    Client, Plaintext,
    Request::{self, *},
    Response::{self, *},
    UserId,
};

const SERVER_URL: &str = "127.0.0.1:39656";

enum Packet {
    Response(Response),
    UserInput(String),
}

fn main() -> std::io::Result<()> {
    let mut client = Client::new().unwrap();
    print_usage(&client)?;
    let (tx, rx) = mpsc::channel();

    spawn_server_call(&tx, AddPrekeys(client.id(), client.publish_prekeys()));
    spawn_read_line_loop(&tx);
    spawn_get_mail_loop(&tx, client.id());

    let mut peer_id = None;
    while let Ok(packet) = rx.recv() {
        use Packet::*;
        match packet {
            Response(Success) => (),
            Response(Error(error)) => panic!(error),
            Response(Prekey(prekey)) => client.initiate(prekey).unwrap(),
            UserInput(line) => match (line.chars().next(), &peer_id) {
                (Some('/'), _) => {
                    let user_id: UserId = serde_json::from_str(&line[1..])?;
                    peer_id = Some(user_id.clone());
                    if !client.has_session(&user_id) {
                        spawn_server_call(&tx, GetPrekey(user_id));
                    }
                }
                (_, Some(user_id)) => {
                    let plaintext = Plaintext(line.as_bytes().to_vec());
                    spawn_server_call(
                        &tx,
                        AddMail(client.send(user_id.clone(), plaintext).unwrap()),
                    );
                }
                (_, None) => {
                    println!("  error: no user_id specified");
                    print_usage(&client)?;
                }
            },
            Response(Mail(bundle)) => {
                for envelope in bundle {
                    let (user_id, plaintext) = client.receive(envelope).unwrap();
                    peer_id = Some(user_id.clone());
                    print!(
                        "{}: {}",
                        serde_json::to_string(&client.id())?,
                        std::str::from_utf8(&plaintext.0).unwrap(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn spawn_read_line_loop(tx: &mpsc::Sender<Packet>) {
    let tx = tx.clone();
    thread::spawn(move || loop {
        let mut buffer = String::new();
        stdin().read_line(&mut buffer).unwrap();
        tx.send(Packet::UserInput(buffer)).unwrap();
    });
}

fn spawn_get_mail_loop(tx: &mpsc::Sender<Packet>, user_id: UserId) {
    let tx = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(time::Duration::from_millis(1000));
        spawn_server_call(&tx, GetMail(user_id.clone()));
    });
}

fn spawn_server_call(tx: &mpsc::Sender<Packet>, request: Request) {
    let tx = tx.clone();
    thread::spawn(move || tx.send(Packet::Response(call_server(request).unwrap())));
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
