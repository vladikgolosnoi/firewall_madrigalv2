use std::{collections::HashMap, net::Ipv4Addr};
use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::HashMap as UserMap, programs::{Xdp, XdpFlags}, Bpf};
use clap::Parser;
use serde::Deserialize;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s3")]
    iface: String,

    #[clap(short, long, default_value = "config.yml")]
    config: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    blocked: Option<Blocked>,
    allowed: Option<HashMap<String, u16>>,
}

#[derive(Debug, Deserialize)]
struct Blocked {
    tcp: Option<String>,
    udp: Option<String>,
    ips: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let config_text = std::fs::read_to_string(&opt.config)
        .with_context(|| format!("Не удалось прочитать файл конфигурации: {}", opt.config))?;
    println!("📄 Загружен config.yml:\n{}", config_text);

    let config: Config = serde_yaml::from_str(&config_text)
        .context("❌ Ошибка парсинга config.yml")?;
    println!("✅ Конфигурация успешно прочитана");

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/firewall"
    ))?;

    if let Some(map) = bpf.map_mut("ALLOWED_HTTP") {
        let mut allowed_http: UserMap<_, u8, u8> = UserMap::try_from(map)?;
        if let Some(allowed) = &config.allowed {
            for (proto, port) in allowed {
                match proto.as_str() {
                    "http1.0" => { allowed_http.insert(0, 1, 0)?; println!("  ✅ http1.0 разрешён (key: 0)"); }
                    "http1.1" => { allowed_http.insert(1, 1, 0)?; println!("  ✅ http1.1 разрешён (key: 1)"); }
                    "http1"   => { allowed_http.insert(2, 1, 0)?; println!("  ✅ http1 разрешён (key: 2)"); }
                    "https1.1"=> { allowed_http.insert(3, 1, 0)?; println!("  ✅ https1.1 разрешён (key: 3)"); }
                    "https2"  => { allowed_http.insert(4, 1, 0)?; println!("  ✅ https2 разрешён (key: 4)"); }
                    "http3"   => { allowed_http.insert(5, 1, 0)?; println!("  ✅ http3 разрешён (key: 5)"); }
                    "dns"     => { allowed_http.insert(53, 1, 0)?; println!("  ✅ DNS разрешён (key: 53)"); }
                    _ => println!("  ❌ Неизвестная версия протокола: {} — пропущено", proto),
                }
            }
        }
    }

    if let Some(map) = bpf.map_mut("BLOCKED_PROTO") {
        let mut proto_map: UserMap<_, u8, u8> = UserMap::try_from(map)?;
        if let Some(blocked) = &config.blocked {
            if blocked.tcp.as_deref() == Some("*") {
                proto_map.insert(6, 1, 0)?; // TCP
                println!("  🔥 TCP заблокирован (proto 6)");
            }
            if blocked.udp.as_deref() == Some("*") {
                proto_map.insert(17, 1, 0)?; // UDP
                println!("  🔥 UDP заблокирован (proto 17)");
            }
        }
    }

    if let Some(map) = bpf.map_mut("BLOCKED_IPS") {
        let mut blocked_ips: UserMap<_, u32, u8> = UserMap::try_from(map)?;
        if let Some(blocked) = &config.blocked {
            if let Some(ips) = &blocked.ips {
                for ip_str in ips {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        blocked_ips.insert(u32::from(ip).to_be(), 1, 0)?;
                        println!("  🚫 IP заблокирован: {}", ip);
                    } else {
                        eprintln!("⚠️ Неверный IP в config.yml: {}", ip_str);
                    }
                }
            }
        }
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").context("xdp_firewall not found")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)?;

    println!("✅ Firewall запущен. Нажми Ctrl+C для выхода.");
    signal::ctrl_c().await?;
    println!("🛑 Завершение работы.");

    Ok(())
}