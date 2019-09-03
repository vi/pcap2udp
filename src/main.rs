#![feature(try_blocks)]
#![feature(checked_duration_since)]

use std::net::SocketAddr;
use std::path::PathBuf;
use structopt::StructOpt;
use pcap_file::PcapReader;
use std::time::{Duration,Instant};
use std::io::Write;

#[derive(StructOpt)]
struct Opt {
    pcap_file: PathBuf,
    skip_bytes: usize,
    bind_addr: SocketAddr,
    send_to: SocketAddr,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    let f = std::fs::File::open(opt.pcap_file)?;
    let r = PcapReader::new(f)?;

    if r.header.magic_number != 0xa1b2c3d4 && r.header.magic_number != 0xd4c3b2a1 {
        Err("Pcap file is not microseconds-based")?;
    }

    let udp = std::net::UdpSocket::bind(opt.bind_addr)?;
    //udp.connect(opt.send_to)?;

    let mut first_ts : Option<Duration> = None;

    let start = Instant::now();

    let so = std::io::stdout();
    let mut so = so.lock();
    for pkt in r {
        so.flush()?;
        let pkt = pkt?;
        let ts = Duration::new(pkt.header.ts_sec as u64, pkt.header.ts_usec * 1000);
        
        if pkt.data.len() < opt.skip_bytes + 12 {
            print!("?");
            continue;
        }
        let content = &pkt.data[opt.skip_bytes..];

        if first_ts == None { first_ts = Some(ts); }
        let first_ts = first_ts.unwrap();

        let _ : Option<()> = try {
            let tm = start.checked_add(ts)?.checked_sub(first_ts)?;
            let now = Instant::now();
            std::thread::sleep(tm.checked_duration_since(now)?);
        };

        if let Err(_) = udp.send_to(content, opt.send_to) {
            let _ = write!(so, "E");
        } else {
            let _ =write!(so, ".");
        }
    }
    let _ = writeln!(so);

    Ok(())
}
