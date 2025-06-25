use colored::Colorize;
use log::{debug, info};

use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

use rusthound_ce::objects::computer::Computer;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Function to resolve all IP address from the LDAP FQDN vector
/// <https://docs.rs/trust-dns-resolver/latest/trust_dns_resolver/index.html>
/// <https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/config.rs>
pub async fn resolving_all_fqdn(
    dns_tcp: bool,
    name_server: &str,
    fqdn_ip: &mut HashMap<String, String>,
    vec_computer: &[Computer],
) {
    info!("Resolving FQDN to IP address started...");
    let copy = fqdn_ip.to_owned();
    for value in copy {
        for computer in vec_computer.iter() {
            if (*computer.properties().name() == value.0) && (*computer.properties().enabled()) {
                debug!("Trying to resolve FQDN: {}", value.0);
                // Resolve FQDN to IP address
                let address = resolver(value.0.to_string(), dns_tcp, name_server).await;
                if let Some(addr) = address {
                    fqdn_ip.insert(value.0.to_owned().to_string(), addr.to_owned().to_string());
                    info!(
                        "IP address for {}: {}",
                        &value.0.to_string().yellow().bold(),
                        &addr.yellow().bold()
                    );
                }
            }
            continue;
        }
    }
    info!("Resolving FQDN to IP address finished!");
}

/// Asynchronous function to resolve IP address from the ldap FQDN
pub async fn resolver(fqdn: String, dns_tcp: bool, name_server: &str) -> Option<String> {
    // Get configuration and options for resolver
    let (c, o) = make_resolver_conf(dns_tcp, name_server);

    // Construct a new Resolver with default configuration options
    let resolver = TokioAsyncResolver::tokio(c, o);

    // Resolver
    let result = resolver.lookup_ip(fqdn);

    match result.await {
        Ok(response) => {
            let address = response.iter().next().expect("no addresses returned!");
            if address.is_ipv4() {
                return Some(address.to_string());
            }
        }
        Err(_err) => {}
    };
    None
}

/// Function to prepare resolver configuration
pub fn make_resolver_conf(dns_tcp: bool, name_server: &str) -> (ResolverConfig, ResolverOpts) {
    let mut c = ResolverConfig::new();
    let mut socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
    let mut dns_protocol = Protocol::Udp;
    if dns_tcp {
        dns_protocol = Protocol::Tcp;
    }
    if !name_server.contains("127.0.0.1") {
        let address = name_server
            .parse::<IpAddr>()
            .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        socket.set_ip(address);
    }

    debug!("Protocol DNS: {:?}", &dns_protocol);
    debug!("Name server DNS: {:?}", name_server.parse::<Ipv4Addr>());

    c.add_name_server(NameServerConfig {
        socket_addr: socket,
        protocol: dns_protocol,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });

    let mut o = ResolverOpts::default();
    o.timeout = Duration::new(0, 10);
    (c, o)
}
