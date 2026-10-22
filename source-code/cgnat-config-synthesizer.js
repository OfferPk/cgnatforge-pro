/**
 * CGNATForge Pro - Multi-Platform Carrier-Grade NAT & NAT64 Configuration Synthesizer
 * 
 * Synthesizes production-hardened configurations for Cisco IOS-XE (ASR 1000/Cat8000),
 * Cisco IOS-XR (ASR 9000), Juniper Junos (MX Series), Linux (nftables/Jool), and A10 Thunder CGN.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CgnatConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(params) {
    const subSubnet = params.subscriberSubnet || '100.64.0.0/10';
    const pubStart = params.publicPoolStart || '198.51.100.1';
    const pubEnd = params.publicPoolEnd || '198.51.100.64';
    const portQuota = params.portQuota || 1024;
    const isDeterministic = Boolean(params.deterministicEnabled);
    const isNat64 = Boolean(params.nat64Enabled);
    const mss = params.tcpMssClamping || 1412;

    let nat64Config = '';
    if (isNat64) {
      nat64Config = `!
! 5. Stateful NAT64 Architecture (IPv6-Only Transition)
nat64 prefix stateful 64:ff9b::/96
nat64 v4 pool NAT64-POOL ${pubStart} ${pubStart}
nat64 v6v4 list V6-SUBSCRIBERS pool NAT64-POOL overload
ipv6 access-list V6-SUBSCRIBERS
 permit ipv6 2001:db8:1::/48 any
!
interface TenGigabitEthernet0/1/0
 description IPV6-SUBSCRIBER-INGRESS
 nat64 inside
 ipv6 verify unicast source reachable-via rx
!
interface TenGigabitEthernet0/2/0
 description IPV4-CORE-EGRESS
 nat64 outside
`;
    }

    let detComment = isDeterministic
      ? `! Deterministic Port Batching Profile: Fixed ${portQuota} Ports per Subscriber
ip nat pool CGN-PUBLIC-POOL ${pubStart} ${pubEnd} prefix-length 24
ip nat settings mode cgn
ip nat settings support-mapping-protocol
ip nat inside source list CGN-SUBSCRIBERS pool CGN-PUBLIC-POOL overload`
      : `! Dynamic PAT with Strict Port Quota Limiting
ip nat pool CGN-PUBLIC-POOL ${pubStart} ${pubEnd} prefix-length 24
ip nat inside source list CGN-SUBSCRIBERS pool CGN-PUBLIC-POOL overload`;

    return `! ==============================================================================
! Cisco ASR 1000 / Catalyst 8000 Production Carrier-Grade NAT (CGNAT) Configuration
! Standards: IETF RFC 6888 | RFC 6598 | RFC 7422 | RFC 5382 (EIM/EIF)
! ==============================================================================

! 1. Global CGNAT Optimization & Resource Limits
ip nat settings mode cgn
ip nat translation max-entries all-host ${portQuota}
ip nat translation timeout 1800
ip nat translation udp-timeout 120
ip nat translation tcp-timeout 1800
ip nat translation finrst-timeout 30

! 2. RFC 6598 Subscriber Access Control List
ip access-list standard CGN-SUBSCRIBERS
 permit 100.64.0.0 0.63.255.255

! 3. Translation Pool & Mapping Architecture
${detComment}
!
! 4. Subscriber Ingress Interface with uRPF & MSS Clamping
interface TenGigabitEthernet0/0/0
 description SUBSCRIBER-ACCESS-AGGREGATION
 ip address 100.64.0.1 255.192.0.0
 ip nat inside
 ip virtual-reassembly in
 ip tcp adjust-mss ${mss}
 ip verify unicast source reachable-via rx
 no shutdown
!
interface TenGigabitEthernet0/0/1
 description TRANSIT-PUBLIC-INTERNET-UPLINK
 ip address ${pubStart} 255.255.255.192
 ip nat outside
 ip virtual-reassembly in
 no shutdown
${nat64Config}`;
  }

  function synthesizeCiscoIosXr(params) {
    const pubStart = params.publicPoolStart || '198.51.100.1';
    const pubEnd = params.publicPoolEnd || '198.51.100.64';
    const portQuota = params.portQuota || 1024;

    return `! ==============================================================================
! Cisco IOS-XR ASR 9000 Service Edge Carrier-Grade NAT Configuration
! ==============================================================================
service-location preferred-active rack 0 slot 0 cpu 0

cgn nat44 profile CGN-DET-PROF
 port-limit ${portQuota}
 mapping-type deterministic
 port-block-size ${portQuota}
 timeouts
  tcp 1800
  udp 120
 !
 address-pool CGN-PUBLIC-POOL
  start-address ${pubStart} end-address ${pubEnd}
 !
 inside-network 100.64.0.0/10
!
interface Bundle-Ether1
 description SUBSCRIBER-INGRESS
 service-profile cgn CGN-DET-PROF inside
!
interface Bundle-Ether2
 description PUBLIC-TRANSIT-EGRESS
 service-profile cgn CGN-DET-PROF outside
`;
  }

  function synthesizeJunos(params) {
    const pubStart = params.publicPoolStart || '198.51.100.1';
    const pubEnd = params.publicPoolEnd || '198.51.100.64';
    const portQuota = params.portQuota || 1024;

    return `# ==============================================================================
# Juniper Junos OS MX-Series MS-MPC / MS-MIC Carrier-Grade NAT Configuration
# ==============================================================================
set services nat pool CGN-PUBLIC-POOL address-range low ${pubStart} high ${pubEnd}
set services nat pool CGN-PUBLIC-POOL port automatic-port-block-allocation block-size ${portQuota}
set services nat pool CGN-PUBLIC-POOL port automatic-port-block-allocation max-blocks-per-address 64

set services nat rule CGN-RULE match-direction input
set services nat rule CGN-RULE term T1 from source-address 100.64.0.0/10
set services nat rule CGN-RULE term T1 then translated source-pool CGN-PUBLIC-POOL
set services nat rule CGN-RULE term T1 then translated translation-type source deterministic

# Stateful NAT64 Rule
set services nat rule NAT64-RULE match-direction input
set services nat rule NAT64-RULE term T1 from source-address 2001:db8:1::/48
set services nat rule NAT64-RULE term T1 from destination-prefix 64:ff9b::/96
set services nat rule NAT64-RULE term T1 then translated translation-type stateful-nat64
`;
  }

  function synthesizeLinux(params) {
    const pubStart = params.publicPoolStart || '198.51.100.1';
    const pubEnd = params.publicPoolEnd || '198.51.100.64';

    return `# ==============================================================================
# Linux Carrier-Grade NAT (nftables) & Jool Stateful NAT64 Configuration
# ==============================================================================
# 1. Enable IPv4 and IPv6 Forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# 2. nftables CGNAT Postrouting Masquerade / SNAT Pool
nft add table ip cgnat
nft add chain ip cgnat postrouting '{ type nat hook postrouting priority 100; }'
nft add rule ip cgnat postrouting ip saddr 100.64.0.0/10 oifname "eth1" snat to ${pubStart}-${pubEnd} persistent

# 3. Jool Open-Source Stateful NAT64 Daemon Initialization
# modprobe jool
# jool instance add --netfilter --pool6 64:ff9b::/96
# jool pool4 add --tcp ${pubStart} 1024-65535
# jool pool4 add --udp ${pubStart} 1024-65535
# jool pool4 add --icmp ${pubStart} 1024-65535
`;
  }

  function synthesizeA10Thunder(params) {
    const pubStart = params.publicPoolStart || '198.51.100.1';
    const pubEnd = params.publicPoolEnd || '198.51.100.64';
    const portQuota = params.portQuota || 1024;

    return `! ==============================================================================
! A10 Networks Thunder CGN Production Fixed-NAT Configuration
! ==============================================================================
cgnv6 nat pool CGN-POOL ${pubStart} ${pubEnd} netmask /24

cgnv6 fixed-nat inside-user 100.64.0.0 /10 nat-ip-list ${pubStart} to ${pubEnd} ports-per-user ${portQuota}

cgnv6 template tcp CGN-TCP-TMP
  idle-timeout 1800
  half-close-timeout 30

cgnv6 template udp CGN-UDP-TMP
  idle-timeout 120
`;
  }

  return {
    synthesizeCiscoIosXe,
    synthesizeCiscoIosXr,
    synthesizeJunos,
    synthesizeLinux,
    synthesizeA10Thunder
  };
}));
