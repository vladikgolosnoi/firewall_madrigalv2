#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map(name = "ALLOWED_HTTP")]
static mut ALLOWED_HTTP: HashMap<u8, u8> = HashMap::<u8, u8>::with_max_entries(64, 0);

#[map(name = "BLOCKED_PROTO")]
static mut BLOCKED_PROTO: HashMap<u8, u8> = HashMap::<u8, u8>::with_max_entries(8, 0);

#[map(name = "BLOCKED_IPS")]
static mut BLOCKED_IPS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, 14)?;
    let proto = unsafe { (*ipv4hdr).proto as u8 };
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    if unsafe { BLOCKED_IPS.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    let source_port = match proto {
        6 => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, 14 + 20)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        17 => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, 14 + 20)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Ok(xdp_action::XDP_DROP),
    };

    // === ALLOWED HTTP ===
    if source_port == 80 {
        let allow = unsafe {
            ALLOWED_HTTP.get(&0).is_some() ||
            ALLOWED_HTTP.get(&1).is_some() ||
            ALLOWED_HTTP.get(&2).is_some()
        };
        if allow {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    if source_port == 443 {
        let allow = unsafe {
            ALLOWED_HTTP.get(&3).is_some() ||
            ALLOWED_HTTP.get(&4).is_some() ||
            ALLOWED_HTTP.get(&5).is_some()
        };
        if allow {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    if source_port == 53 {
        if unsafe { ALLOWED_HTTP.get(&53).is_some() } {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    if unsafe { BLOCKED_PROTO.get(&proto) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_DROP)
}