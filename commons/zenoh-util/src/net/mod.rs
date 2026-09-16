//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use std::net::{IpAddr, Ipv6Addr};
#[cfg(unix)]
use std::sync::RwLock;

#[cfg(unix)]
use lazy_static::lazy_static;
#[cfg(unix)]
use pnet_datalink::NetworkInterface;
use tokio::net::{TcpSocket, UdpSocket};
use zenoh_core::zconfigurable;
#[cfg(unix)]
use zenoh_core::{zread, zwrite};
#[cfg(unix)]
use zenoh_result::zerror;
use zenoh_result::{bail, ZResult};

zconfigurable! {
    static ref WINDOWS_GET_ADAPTERS_ADDRESSES_BUF_SIZE: u32 = 8192;
    static ref WINDOWS_GET_ADAPTERS_ADDRESSES_MAX_RETRIES: u32 = 3;
}

#[cfg(unix)]
lazy_static! {
    static ref IFACES: RwLock<Vec<NetworkInterface>> = RwLock::new(pnet_datalink::interfaces());
}

/// Reads the network interfaces from the host into the cache, and reports whether
/// its contents changed.
#[cfg(unix)]
pub fn refresh_interfaces() -> bool {
    cache_interfaces(enumerate_interfaces())
}

/// Puts an interface list of the caller's choosing in the cache, in place of the
/// host's, and reports whether its contents changed.
///
/// What sits in that cache decides which addresses the node advertises and which
/// ones it binds, so outside a test nothing linked into the process gets to choose
/// it but the host. That is what the feature gate is for: a plugin or a crate
/// anywhere in the dependency graph would otherwise be able to point a node at
/// addresses of its own choosing, and the node would advertise them truthfully.
#[cfg(all(unix, feature = "test"))]
pub fn replace_interfaces(ifaces: Vec<NetworkInterface>) -> bool {
    cache_interfaces(ifaces)
}

/// Reads the network interfaces from the host, bypassing the cache every other
/// function in this module derives from.
#[cfg(unix)]
fn enumerate_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
}

/// Replaces the cached interface list, and reports whether its contents changed.
///
/// A changed list says nothing about whether any derived address set changed with
/// it: the derivations narrow by flags and by address family, so they can stay the
/// same across a change and differ without one.
#[cfg(unix)]
fn cache_interfaces(ifaces: Vec<NetworkInterface>) -> bool {
    let mut cached = zwrite!(IFACES);
    let changed = *cached != ifaces;
    *cached = ifaces;

    changed
}

/// Reports that nothing changed, because there is no cache to refresh here.
///
/// Every interface lookup on this target asks the operating system for itself, so a
/// caller that polls the host already sees the current view without this doing
/// anything. It exists on every target so that such a caller needs no `cfg` of its
/// own, which is what keeps the poll buildable off unix.
#[cfg(not(unix))]
pub fn refresh_interfaces() -> bool {
    false
}

#[cfg(windows)]
/// # Safety
/// The caller must ensure the `af_spec`` is valid, which will be used by
/// `winapi::um::iphlpapi::GetAdaptersAddresses`.
unsafe fn get_adapters_addresses(af_spec: i32) -> ZResult<Vec<u8>> {
    use winapi::um::iptypes::IP_ADAPTER_ADDRESSES_LH;

    let mut ret;
    let mut retries = 0;
    let mut size: u32 = *WINDOWS_GET_ADAPTERS_ADDRESSES_BUF_SIZE;
    let mut buffer: Vec<u8>;
    loop {
        buffer = Vec::with_capacity(size as usize);
        // SAFETY: Call the unsafe function `GetAdaptersAddresses`.
        ret = unsafe {
            winapi::um::iphlpapi::GetAdaptersAddresses(
                af_spec.try_into().unwrap(),
                0,
                std::ptr::null_mut(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if ret != winapi::shared::winerror::ERROR_BUFFER_OVERFLOW {
            break;
        }
        if retries >= *WINDOWS_GET_ADAPTERS_ADDRESSES_MAX_RETRIES {
            break;
        }
        retries += 1;
    }

    if ret != 0 {
        bail!("GetAdaptersAddresses returned {}", ret)
    }

    Ok(buffer)
}
pub fn get_interface(name: &str) -> ZResult<Option<IpAddr>> {
    #[cfg(unix)]
    {
        for iface in zread!(IFACES).iter() {
            if iface.name == name {
                for ifaddr in &iface.ips {
                    if ifaddr.is_ipv4() {
                        return Ok(Some(ifaddr.ip()));
                    }
                }
            }
            for ifaddr in &iface.ips {
                if ifaddr.ip().to_string() == name {
                    return Ok(Some(ifaddr.ip()));
                }
            }
        }
        Ok(None)
    }

    #[cfg(windows)]
    {
        unsafe {
            use winapi::um::iptypes::IP_ADAPTER_ADDRESSES_LH;

            use crate::ffi;

            let buffer = get_adapters_addresses(winapi::shared::ws2def::AF_INET)?;

            let mut next_iface = (buffer.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH).as_ref();
            while let Some(iface) = next_iface {
                if name == ffi::pstr_to_string(iface.AdapterName)
                    || name == ffi::pwstr_to_string(iface.FriendlyName)
                    || name == ffi::pwstr_to_string(iface.Description)
                {
                    let mut next_ucast_addr = iface.FirstUnicastAddress.as_ref();
                    while let Some(ucast_addr) = next_ucast_addr {
                        if let Ok(ifaddr) = ffi::win::sockaddr_to_addr(ucast_addr.Address) {
                            if ifaddr.is_ipv4() {
                                return Ok(Some(ifaddr.ip()));
                            }
                        }
                        next_ucast_addr = ucast_addr.Next.as_ref();
                    }
                }

                let mut next_ucast_addr = iface.FirstUnicastAddress.as_ref();
                while let Some(ucast_addr) = next_ucast_addr {
                    if let Ok(ifaddr) = ffi::win::sockaddr_to_addr(ucast_addr.Address) {
                        if ifaddr.ip().to_string() == name {
                            return Ok(Some(ifaddr.ip()));
                        }
                    }
                    next_ucast_addr = ucast_addr.Next.as_ref();
                }
                next_iface = iface.Next.as_ref();
            }
            Ok(None)
        }
    }
}

/// Get the network interface to bind the UDP sending port to when not specified by user
pub fn get_multicast_interfaces() -> Vec<IpAddr> {
    #[cfg(unix)]
    {
        zread!(IFACES)
            .iter()
            .filter_map(|iface| {
                if iface.is_up() && iface.is_running() && iface.is_multicast() {
                    for ipaddr in &iface.ips {
                        if ipaddr.is_ipv4() {
                            return Some(ipaddr.ip());
                        }
                    }
                }
                None
            })
            .collect()
    }
    #[cfg(windows)]
    {
        // On windows, bind to [::], the system will select the default interface
        vec![IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)]
    }
}

pub fn get_local_addresses(interface: Option<&str>) -> ZResult<Vec<IpAddr>> {
    #[cfg(unix)]
    {
        Ok(zread!(IFACES)
            .iter()
            .filter(|iface| {
                if let Some(interface) = interface.as_ref() {
                    if iface.name != *interface {
                        return false;
                    }
                }
                iface.is_up() && iface.is_running()
            })
            .flat_map(|iface| iface.ips.clone())
            .map(|ipnet| ipnet.ip())
            .collect())
    }

    #[cfg(windows)]
    {
        unsafe {
            use winapi::um::iptypes::IP_ADAPTER_ADDRESSES_LH;

            use crate::ffi;

            let buffer = get_adapters_addresses(winapi::shared::ws2def::AF_UNSPEC)?;

            let mut result = vec![];
            let mut next_iface = (buffer.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH).as_ref();
            while let Some(iface) = next_iface {
                if let Some(interface) = interface.as_ref() {
                    if ffi::pstr_to_string(iface.AdapterName) != *interface {
                        continue;
                    }
                }
                let mut next_ucast_addr = iface.FirstUnicastAddress.as_ref();
                while let Some(ucast_addr) = next_ucast_addr {
                    if let Ok(ifaddr) = ffi::win::sockaddr_to_addr(ucast_addr.Address) {
                        result.push(ifaddr.ip());
                    }
                    next_ucast_addr = ucast_addr.Next.as_ref();
                }
                next_iface = iface.Next.as_ref();
            }
            Ok(result)
        }
    }
}

/// Get the network interface to bind the UDP sending port to when not specified by user
pub fn get_unicast_addresses_of_multicast_interfaces() -> Vec<IpAddr> {
    #[cfg(unix)]
    {
        zread!(IFACES)
            .iter()
            .filter(|iface| iface.is_up() && iface.is_running() && iface.is_multicast())
            .flat_map(|iface| {
                iface
                    .ips
                    .iter()
                    .filter(|ip| !ip.ip().is_multicast())
                    .map(|x| x.ip())
                    .collect::<Vec<IpAddr>>()
            })
            .collect()
    }
    #[cfg(windows)]
    {
        // On windows, bind to [::] or [::], the system will select the default interface
        vec![]
    }
}

pub fn get_unicast_addresses_of_interface(name: &str) -> ZResult<Vec<IpAddr>> {
    #[cfg(unix)]
    {
        match zread!(IFACES).iter().find(|iface| iface.name == name) {
            Some(iface) => {
                if !iface.is_up() {
                    bail!("Interface {name} is not up");
                }
                if !iface.is_running() {
                    bail!("Interface {name} is not running");
                }
                let addrs = iface
                    .ips
                    .iter()
                    .filter(|ip| !ip.ip().is_multicast())
                    .map(|x| x.ip())
                    .collect::<Vec<IpAddr>>();
                Ok(addrs)
            }
            None => bail!("Interface {name} not found"),
        }
    }

    #[cfg(windows)]
    {
        unsafe {
            use winapi::um::iptypes::IP_ADAPTER_ADDRESSES_LH;

            use crate::ffi;

            let buffer = get_adapters_addresses(winapi::shared::ws2def::AF_INET)?;

            let mut addrs = vec![];
            let mut next_iface = (buffer.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH).as_ref();
            while let Some(iface) = next_iface {
                if name == ffi::pstr_to_string(iface.AdapterName)
                    || name == ffi::pwstr_to_string(iface.FriendlyName)
                    || name == ffi::pwstr_to_string(iface.Description)
                {
                    let mut next_ucast_addr = iface.FirstUnicastAddress.as_ref();
                    while let Some(ucast_addr) = next_ucast_addr {
                        if let Ok(ifaddr) = ffi::win::sockaddr_to_addr(ucast_addr.Address) {
                            addrs.push(ifaddr.ip());
                        }
                        next_ucast_addr = ucast_addr.Next.as_ref();
                    }
                }
                next_iface = iface.Next.as_ref();
            }
            Ok(addrs)
        }
    }
}

pub fn get_index_of_interface(addr: IpAddr) -> ZResult<u32> {
    #[cfg(unix)]
    {
        zread!(IFACES)
            .iter()
            .find(|iface| iface.ips.iter().any(|ipnet| ipnet.ip() == addr))
            .map(|iface| iface.index)
            .ok_or_else(|| zerror!("No interface found with address {addr}").into())
    }
    #[cfg(windows)]
    {
        unsafe {
            use winapi::um::iptypes::IP_ADAPTER_ADDRESSES_LH;

            use crate::ffi;

            let buffer = get_adapters_addresses(winapi::shared::ws2def::AF_INET)?;

            let mut next_iface = (buffer.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH).as_ref();
            while let Some(iface) = next_iface {
                let mut next_ucast_addr = iface.FirstUnicastAddress.as_ref();
                while let Some(ucast_addr) = next_ucast_addr {
                    if let Ok(ifaddr) = ffi::win::sockaddr_to_addr(ucast_addr.Address) {
                        if ifaddr.ip() == addr {
                            return Ok(iface.Ipv6IfIndex);
                        }
                    }
                    next_ucast_addr = ucast_addr.Next.as_ref();
                }
                next_iface = iface.Next.as_ref();
            }
            bail!("No interface found with address {addr}")
        }
    }
}

pub fn get_interface_names_by_addr(addr: IpAddr) -> ZResult<Vec<String>> {
    #[cfg(unix)]
    {
        if addr.is_unspecified() {
            Ok(zread!(IFACES)
                .iter()
                .map(|iface| iface.name.clone())
                .collect::<Vec<String>>())
        } else {
            let addr = addr.to_canonical();
            Ok(zread!(IFACES)
                .iter()
                .filter(|iface| iface.ips.iter().any(|ipnet| ipnet.ip() == addr))
                .map(|iface| iface.name.clone())
                .collect::<Vec<String>>())
        }
    }
    #[cfg(windows)]
    {
        let mut result = vec![];
        unsafe {
            use winapi::um::iptypes::IP_ADAPTER_ADDRESSES_LH;

            use crate::ffi;

            let buffer = get_adapters_addresses(winapi::shared::ws2def::AF_UNSPEC)?;

            if addr.is_unspecified() {
                let mut next_iface = (buffer.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH).as_ref();
                while let Some(iface) = next_iface {
                    result.push(ffi::pstr_to_string(iface.AdapterName));
                    next_iface = iface.Next.as_ref();
                }
            } else {
                let addr = addr.to_canonical();
                let mut next_iface = (buffer.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH).as_ref();
                while let Some(iface) = next_iface {
                    let mut next_ucast_addr = iface.FirstUnicastAddress.as_ref();
                    while let Some(ucast_addr) = next_ucast_addr {
                        if let Ok(ifaddr) = ffi::win::sockaddr_to_addr(ucast_addr.Address) {
                            if ifaddr.ip() == addr {
                                result.push(ffi::pstr_to_string(iface.AdapterName));
                            }
                        }
                        next_ucast_addr = ucast_addr.Next.as_ref();
                    }
                    next_iface = iface.Next.as_ref();
                }
            }
        }
        Ok(result)
    }
}

pub fn get_ipv4_ipaddrs(interface: Option<&str>, noloopback: bool) -> Vec<IpAddr> {
    get_local_addresses(interface)
        .unwrap_or_else(|_| vec![])
        .drain(..)
        .filter_map(|x| match x {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        })
        .filter(|x| {
            if noloopback && x.is_loopback() {
                return false;
            }
            !x.is_multicast()
        })
        .map(IpAddr::V4)
        .collect()
}

pub fn get_ipv6_ipaddrs(interface: Option<&str>, noloopback: bool) -> Vec<IpAddr> {
    const fn is_unicast_link_local(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xffc0) == 0xfe80
    }

    let ipaddrs = get_local_addresses(interface).unwrap_or_else(|_| vec![]);

    // Get first all IPv4 addresses
    let ipv4_iter = ipaddrs
        .iter()
        .filter_map(|x| match x {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        })
        .filter(|x| {
            if noloopback && x.is_loopback() {
                return false;
            }
            !x.is_link_local() && !x.is_multicast() && !x.is_broadcast()
        });

    // Get next all IPv6 addresses
    let ipv6_iter = ipaddrs.iter().filter_map(|x| match x {
        IpAddr::V4(_) => None,
        IpAddr::V6(a) => Some(a),
    });

    // First match non-linklocal IPv6 addresses
    let nll_ipv6_addrs = ipv6_iter
        .clone()
        .filter(|x| {
            if noloopback && x.is_loopback() {
                return false;
            }
            !x.is_multicast() && !is_unicast_link_local(x)
        })
        .map(|x| IpAddr::V6(*x));

    // Second match public IPv4 addresses
    let pub_ipv4_addrs = ipv4_iter
        .clone()
        .filter(|x| !x.is_private())
        .map(|x| IpAddr::V4(*x));

    // Third match linklocal IPv6 addresses
    let yll_ipv6_addrs = ipv6_iter
        .filter(|x| {
            if noloopback && x.is_loopback() {
                return false;
            }
            !x.is_multicast() && is_unicast_link_local(x)
        })
        .map(|x| IpAddr::V6(*x));

    // Fourth match private IPv4 addresses
    let priv_ipv4_addrs = ipv4_iter
        .clone()
        .filter(|x| x.is_private())
        .map(|x| IpAddr::V4(*x));

    // Extend
    nll_ipv6_addrs
        .chain(pub_ipv4_addrs)
        .chain(yll_ipv6_addrs)
        .chain(priv_ipv4_addrs)
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_bind_to_device_tcp_socket(socket: &TcpSocket, iface: &str) -> ZResult<()> {
    socket.bind_device(Some(iface.as_bytes()))?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_bind_to_device_udp_socket(socket: &UdpSocket, iface: &str) -> ZResult<()> {
    socket.bind_device(Some(iface.as_bytes()))?;
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "windows"
))]
pub fn set_bind_to_device_tcp_socket(socket: &TcpSocket, iface: &str) -> ZResult<()> {
    tracing::warn!("Binding the socket {socket:?} to the interface {iface} is not supported on macOS, iOS, FreeBSD and Windows");
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "windows"
))]
pub fn set_bind_to_device_udp_socket(socket: &UdpSocket, iface: &str) -> ZResult<()> {
    tracing::warn!("Binding the socket {socket:?} to the interface {iface} is not supported on macOS, iOS, FreeBSD and Windows");
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{Mutex, MutexGuard, PoisonError},
    };

    use pnet_datalink::{MacAddr, NetworkInterface};

    use super::*;

    #[test]
    fn readers_observe_a_replaced_interface_list() {
        let _guard = lock_cache();

        assert!(cache_interfaces(vec![test_interface(
            UP | RUNNING | MULTICAST
        )]));

        assert_eq!(get_interface(TEST_NAME).unwrap(), Some(TEST_ADDR));
        assert_eq!(get_multicast_interfaces(), vec![TEST_ADDR]);
        assert_eq!(get_local_addresses(None).unwrap(), vec![TEST_ADDR]);
        assert_eq!(
            get_unicast_addresses_of_multicast_interfaces(),
            vec![TEST_ADDR]
        );
        assert_eq!(
            get_unicast_addresses_of_interface(TEST_NAME).unwrap(),
            vec![TEST_ADDR]
        );
        assert_eq!(get_index_of_interface(TEST_ADDR).unwrap(), TEST_INDEX);
        assert_eq!(
            get_interface_names_by_addr(TEST_ADDR).unwrap(),
            vec![TEST_NAME.to_string()]
        );
        assert_eq!(
            get_interface_names_by_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).unwrap(),
            vec![TEST_NAME.to_string()]
        );

        assert!(cache_interfaces(Vec::new()));

        assert_eq!(get_interface(TEST_NAME).unwrap(), None);
        assert!(get_multicast_interfaces().is_empty());
        assert!(get_local_addresses(None).unwrap().is_empty());
        assert!(get_unicast_addresses_of_multicast_interfaces().is_empty());
        assert!(get_unicast_addresses_of_interface(TEST_NAME).is_err());
        assert!(get_index_of_interface(TEST_ADDR).is_err());
        assert!(get_interface_names_by_addr(TEST_ADDR).unwrap().is_empty());
        assert!(
            get_interface_names_by_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .unwrap()
                .is_empty()
        );

        refresh_interfaces();
    }

    #[test]
    fn the_multicast_derivation_narrows_the_raw_enumeration() {
        let _guard = lock_cache();

        cache_interfaces(vec![test_interface(UP | RUNNING)]);
        assert!(get_multicast_interfaces().is_empty());
        assert_eq!(get_ipv4_ipaddrs(None, true), vec![TEST_ADDR]);

        cache_interfaces(vec![test_interface(UP | MULTICAST)]);
        assert!(get_multicast_interfaces().is_empty());
        assert!(get_ipv4_ipaddrs(None, true).is_empty());

        refresh_interfaces();
    }

    #[test]
    fn a_mac_only_difference_changes_the_cache_but_no_derived_address() {
        let _guard = lock_cache();

        let iface = test_interface(UP | RUNNING | MULTICAST);
        assert!(cache_interfaces(vec![iface.clone()]));
        assert!(!cache_interfaces(vec![iface.clone()]));

        let renamed_mac = NetworkInterface {
            mac: Some(MacAddr::new(2, 2, 2, 2, 2, 2)),
            ..iface
        };
        assert!(cache_interfaces(vec![renamed_mac]));
        assert_eq!(get_multicast_interfaces(), vec![TEST_ADDR]);
        assert_eq!(get_ipv4_ipaddrs(None, true), vec![TEST_ADDR]);

        refresh_interfaces();
    }

    #[test]
    fn refreshing_re_enumerates_the_host() {
        let _guard = lock_cache();

        let host_names = enumerate_interfaces()
            .iter()
            .map(|iface| iface.name.clone())
            .collect::<Vec<String>>();
        assert!(!host_names.is_empty());

        cache_interfaces(Vec::new());
        assert!(
            get_interface_names_by_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .unwrap()
                .is_empty()
        );

        assert!(refresh_interfaces());
        assert_eq!(
            get_interface_names_by_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).unwrap(),
            host_names
        );
    }

    const TEST_NAME: &str = "zenohtest0";
    const TEST_INDEX: u32 = 4242;
    const TEST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    const UP: u32 = libc::IFF_UP as u32;
    const RUNNING: u32 = libc::IFF_RUNNING as u32;
    const MULTICAST: u32 = libc::IFF_MULTICAST as u32;

    /// The interface cache is process global, so no two of these tests may run at once.
    static CACHE_LOCK: Mutex<()> = Mutex::new(());

    fn lock_cache() -> MutexGuard<'static, ()> {
        CACHE_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn test_interface(flags: u32) -> NetworkInterface {
        NetworkInterface {
            name: TEST_NAME.to_string(),
            description: String::new(),
            index: TEST_INDEX,
            mac: Some(MacAddr::new(1, 1, 1, 1, 1, 1)),
            ips: vec!["192.0.2.1/24".parse().unwrap()],
            flags,
        }
    }
}

/// The interface poll calls the refresh with no `cfg` of its own, from a crate a
/// diff on this file cannot see, so the entry point has to resolve wherever that
/// crate builds. This is the arm that has no cache behind it.
#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;

    #[test]
    fn refreshing_reports_no_change_where_there_is_no_cache() {
        assert!(!refresh_interfaces());
    }
}
