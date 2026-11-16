//! Resolve client identity across an explicit proxy trust boundary.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Resolve the client IP from the peer and a validated proxy chain.
///
/// Only trusted peers may supply `X-Forwarded-For`. Traverse their
/// chain from right to left, stopping at the first untrusted address.
/// If every address is trusted, use the leftmost as the furthest origin.
/// Missing peer metadata or an unusable trusted chain yields `None`.
///
/// Untrusted peers identify themselves by their socket address; their
/// forwarded headers are ignored. For trusted peers, every field and
/// comma-separated hop must contain a plain IP address. A missing,
/// empty, non-text, or malformed chain is unknown, even when the bad
/// entry lies beyond the first untrusted hop. Other client-IP headers
/// are ignored to avoid conflicting sources of identity.
///
/// Peers and reported hops use IPv4-mapped normalization; callers must
/// supply the normalized networks from `Config`. Native IPv6 addresses
/// retain all 128 bits; any throttle grouping belongs to the consumer.
/// Call before the gate strips forwarding headers. Resolution does not
/// authorize forwarding those headers to the upstream.
///
/// Trust assumes that each configured proxy correctly appends or
/// replaces `X-Forwarded-For`. Broad ranges can include clients capable
/// of spoofing headers, so use narrow proxy addresses or isolated
/// networks. Docker addresses must be pinned or covered by such a
/// network. Private, loopback, and container addresses receive no
/// implicit trust.
///
/// For example, peer `10.0.0.1` and chain `203.0.113.42, 10.0.0.2`
/// yield `203.0.113.42` when `10.0.0.0/24` is trusted, or `10.0.0.1`
/// when no proxies are trusted.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Pending IP-based throttling and allowlist consumers"
    )
)]
pub(crate) fn resolve_client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxy_cidrs: &[IpNet],
) -> Option<IpAddr> {
    let peer = normalize_ip(peer?.ip());
    if !is_trusted_proxy(peer, trusted_proxy_cidrs) {
        return Some(peer);
    }

    // Validate the entire chain before selecting a boundary: malformed
    // entries to its left must not be silently ignored.
    let chain = parse_forwarded_chain(headers)?;
    chain
        .iter()
        .rev()
        .find(|ip| !is_trusted_proxy(**ip, trusted_proxy_cidrs))
        .or_else(|| chain.first())
        .copied()
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxy_cidrs: &[IpNet]) -> bool {
    trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(&ip))
}

fn parse_forwarded_chain(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let mut chain = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        for entry in value.to_str().ok()?.split(',') {
            chain.push(normalize_ip(entry.trim().parse().ok()?));
        }
    }
    // A trusted peer without a reported origin cannot identify a
    // client.
    if chain.is_empty() {
        return None;
    }
    Some(chain)
}

/// Normalize IPv4-mapped IPv6 addresses without changing native IPv6.
///
/// For example, `::ffff:192.0.2.4` becomes `192.0.2.4`, while
/// `2001:db8::4` remains `2001:db8::4`.
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::ConnectInfo;
    use axum::http::HeaderValue;
    use tokio::net::TcpListener;

    #[test]
    fn direct_peers_preserve_native_addresses_and_normalize_mapped_ipv4() {
        for (peer, expected) in [
            ("192.0.2.4:1234", "192.0.2.4"),
            ("[2001:db8::1234:5678]:1234", "2001:db8::1234:5678"),
            ("[::ffff:192.0.2.4]:1234", "192.0.2.4"),
        ] {
            assert_eq!(
                resolve_client_ip(Some(peer.parse().unwrap()), &HeaderMap::new(), &[]),
                Some(expected.parse().unwrap())
            );
        }
    }

    #[test]
    fn missing_peer_is_unknown_even_with_a_valid_chain() {
        let headers = headers(&["203.0.113.42"]);
        assert_eq!(resolve_client_ip(None, &headers, &trusted_proxies()), None);
    }

    #[test]
    fn untrusted_peer_ignores_all_forwarding_claims() {
        let headers = headers(&["203.0.113.42", "invalid,,"]);
        let peer = "192.0.2.4:1234".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted_proxies()),
            Some(peer.ip())
        );
    }

    #[test]
    fn empty_trust_list_ignores_forwarding_claims() {
        let peer = "10.0.0.1:1234".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers(&["203.0.113.42"]), &[]),
            Some(peer.ip())
        );
    }

    #[test]
    fn trusted_peer_resolves_a_single_reported_client() {
        assert_eq!(
            resolve(&["203.0.113.42"]),
            Some("203.0.113.42".parse().unwrap())
        );
    }

    #[test]
    fn multiple_trusted_hops_are_skipped() {
        assert_eq!(
            resolve(&["203.0.113.42, 10.0.0.2, 10.0.0.3"]),
            Some("203.0.113.42".parse().unwrap())
        );
    }

    #[test]
    fn first_untrusted_hop_prevents_leftmost_spoofing() {
        assert_eq!(
            resolve(&["198.51.100.99, 203.0.113.42, 10.0.0.2"]),
            Some("203.0.113.42".parse().unwrap())
        );
    }

    #[test]
    fn repeated_fields_preserve_chain_order() {
        assert_eq!(
            resolve(&["198.51.100.99, 203.0.113.42", "192.0.2.8, 10.0.0.2"]),
            Some("192.0.2.8".parse().unwrap())
        );
    }

    #[test]
    fn entirely_trusted_chain_returns_leftmost_address() {
        assert_eq!(
            resolve(&["10.0.0.4, 10.0.0.3", "10.0.0.2"]),
            Some("10.0.0.4".parse().unwrap())
        );
    }

    #[test]
    fn missing_forwarded_chain_is_unknown_for_trusted_peer() {
        assert_eq!(resolve(&[]), None);
    }

    #[test]
    fn empty_entries_invalidate_the_entire_chain() {
        for value in [
            "",
            "  ",
            ",203.0.113.42",
            "203.0.113.42,,10.0.0.2",
            "203.0.113.42,",
        ] {
            assert_eq!(resolve(&[value]), None, "{value:?}");
        }
        assert_eq!(resolve(&["203.0.113.42", ""]), None);
    }

    #[test]
    fn malformed_entries_left_of_trust_boundary_invalidate_chain() {
        for value in [
            "invalid",
            "192.0.2.1:80",
            "[2001:db8::1]:80",
            "fe80::1%eth0",
        ] {
            assert_eq!(
                resolve(&[value, "203.0.113.42, 10.0.0.2"]),
                None,
                "{value:?}"
            );
        }
    }

    #[test]
    fn non_text_forwarded_field_invalidates_chain() {
        let mut headers = headers(&["203.0.113.42"]);
        headers.append("x-forwarded-for", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            resolve_client_ip(
                Some("10.0.0.1:1234".parse().unwrap()),
                &headers,
                &trusted_proxies()
            ),
            None
        );
    }

    #[test]
    fn unsupported_headers_do_not_supply_client_identity() {
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", "for=203.0.113.42".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.42".parse().unwrap());
        assert_eq!(
            resolve_client_ip(
                Some("10.0.0.1:1234".parse().unwrap()),
                &headers,
                &trusted_proxies()
            ),
            None
        );
    }

    #[test]
    fn mapped_peer_matches_ipv4_trust_network() {
        assert_eq!(
            resolve_client_ip(
                Some("[::ffff:10.0.0.1]:1234".parse().unwrap()),
                &headers(&["203.0.113.42"]),
                &trusted_proxies()
            ),
            Some("203.0.113.42".parse().unwrap())
        );
    }

    #[test]
    fn mapped_hops_are_normalized_before_trust_checks_and_return() {
        assert_eq!(
            resolve(&["::ffff:203.0.113.42, ::ffff:10.0.0.2"]),
            Some("203.0.113.42".parse().unwrap())
        );
    }

    #[test]
    fn whitespace_is_trimmed_and_native_ipv6_precision_is_preserved() {
        assert_eq!(
            resolve(&[" 2001:db8::abcd:1234 , 10.0.0.2 "]),
            Some("2001:db8::abcd:1234".parse().unwrap())
        );
    }

    #[test]
    fn native_ipv6_trust_does_not_implicitly_trust_ipv4() {
        let peer = "192.0.2.4:1234".parse().unwrap();
        assert_eq!(
            resolve_client_ip(
                Some(peer),
                &headers(&["203.0.113.42"]),
                &["::/0".parse().unwrap()]
            ),
            Some(peer.ip())
        );
    }

    #[tokio::test]
    async fn connection_info_supplies_the_actual_loopback_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().fallback(
            |ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap| async move {
                resolve_client_ip(Some(peer), &headers, &[])
                    .unwrap()
                    .to_string()
            },
        );
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}"))
            .header("x-forwarded-for", "203.0.113.42")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "127.0.0.1");
        server.abort();
    }

    #[tokio::test]
    async fn connection_info_enables_explicit_loopback_proxy_trust() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().fallback(
            |ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap| async move {
                resolve_client_ip(Some(peer), &headers, &["127.0.0.1/32".parse().unwrap()])
                    .unwrap()
                    .to_string()
            },
        );
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}"))
            .header("x-forwarded-for", "203.0.113.42")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "203.0.113.42");
        server.abort();
    }

    fn resolve(values: &[&str]) -> Option<IpAddr> {
        resolve_client_ip(
            Some("10.0.0.1:1234".parse().unwrap()),
            &headers(values),
            &trusted_proxies(),
        )
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", value.parse().unwrap());
        }
        headers
    }

    fn trusted_proxies() -> Vec<IpNet> {
        vec!["10.0.0.0/24".parse().unwrap()]
    }
}
