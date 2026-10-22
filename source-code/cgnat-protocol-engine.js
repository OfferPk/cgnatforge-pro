/**
 * CGNATForge Pro - IETF RFC 6888, RFC 6598, RFC 7422 & RFC 6146 Protocol Engine
 * 
 * Provides deterministic CGNAT mapping algorithms, lawful intercept reverse lookups,
 * stateful NAT64 address synthesis, packet forging with IP/TCP/CRC32 checksums,
 * Wireshark hex formatting, and binary PCAP generation.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CgnatProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Constants
  const RFC6598_PREFIX = '100.64.0.0/10';
  const NAT64_WELL_KNOWN_PREFIX = '64:ff9b::/96';
  const MIN_PORT = 1024;
  const MAX_PORT = 65535;

  function ipv4ToInt(ipStr) {
    const parts = (ipStr || '0.0.0.0').trim().split('.');
    if (parts.length !== 4) return 0;
    return (((parseInt(parts[0], 10) & 0xff) << 24) |
            ((parseInt(parts[1], 10) & 0xff) << 16) |
            ((parseInt(parts[2], 10) & 0xff) << 8) |
             (parseInt(parts[3], 10) & 0xff)) >>> 0;
  }

  function intToIpv4(intVal) {
    return [
      (intVal >>> 24) & 0xff,
      (intVal >>> 16) & 0xff,
      (intVal >>> 8) & 0xff,
      intVal & 0xff
    ].join('.');
  }

  function parseMac(macStr) {
    if (!macStr) return [0, 0, 0, 0, 0, 0];
    const clean = macStr.replace(/[^a-fA-F0-9]/g, '');
    if (clean.length !== 12) return [0, 0, 0, 0, 0, 0];
    const bytes = [];
    for (let i = 0; i < 12; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    return bytes;
  }

  function formatMac(bytes) {
    if (!bytes || bytes.length !== 6) return '00:00:00:00:00:00';
    return bytes.map(b => b.toString(16).padStart(2, '0')).join(':');
  }

  function calculateCrc32(byteArray) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < byteArray.length; i++) {
      crc ^= byteArray[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
      }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function calculateIpChecksum(headerBytes) {
    let sum = 0;
    for (let i = 0; i < headerBytes.length; i += 2) {
      const word = (headerBytes[i] << 8) + (headerBytes[i + 1] || 0);
      sum += word;
    }
    while ((sum >> 16) > 0) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    return (~sum) & 0xffff;
  }

  /**
   * RFC 7422 Deterministic CGNAT Forward Mapping:
   * Maps an internal subscriber IP (e.g. from 100.64.0.0/10) to a deterministic public IPv4 + port block.
   */
  function calculateDeterministicMapping(params) {
    const subscriberIpStr = params.subscriberIp || '100.64.1.50';
    const subscriberBaseStr = params.subscriberBase || '100.64.0.0';
    const publicPoolStartStr = params.publicPoolStart || '198.51.100.1';
    const publicPoolEndStr = params.publicPoolEnd || '198.51.100.64';
    const portBlockSize = Math.max(64, Math.min(8192, parseInt(params.portBlockSize, 10) || 1024));
    const portStart = Math.max(1024, parseInt(params.portStart, 10) || MIN_PORT);
    const portEnd = Math.min(65535, parseInt(params.portEnd, 10) || MAX_PORT);

    const availablePortsPerIp = (portEnd - portStart + 1);
    const subscribersPerPublicIp = Math.floor(availablePortsPerIp / portBlockSize);

    const subInt = ipv4ToInt(subscriberIpStr);
    const subBaseInt = ipv4ToInt(subscriberBaseStr);
    const pubStartInt = ipv4ToInt(publicPoolStartStr);
    const pubEndInt = ipv4ToInt(publicPoolEndStr);

    const subscriberIndex = subInt - subBaseInt;
    const totalPublicIps = (pubEndInt - pubStartInt + 1);
    const maxSubscribersSupported = totalPublicIps * subscribersPerPublicIp;

    if (subscriberIndex < 0 || subscriberIndex >= maxSubscribersSupported) {
      return {
        success: false,
        error: `Subscriber IP ${subscriberIpStr} is out of deterministic range (Supports ${maxSubscribersSupported} subscribers across ${totalPublicIps} public IPs).`,
        subscriberIndex: subscriberIndex,
        maxSubscribersSupported: maxSubscribersSupported
      };
    }

    const publicIpOffset = Math.floor(subscriberIndex / subscribersPerPublicIp);
    const blockIndexOnIp = subscriberIndex % subscribersPerPublicIp;
    const assignedPublicIpInt = pubStartInt + publicIpOffset;
    const assignedPublicIpStr = intToIpv4(assignedPublicIpInt);

    const startPort = portStart + (blockIndexOnIp * portBlockSize);
    const endPort = startPort + portBlockSize - 1;

    return {
      success: true,
      subscriberIp: subscriberIpStr,
      subscriberIndex: subscriberIndex,
      assignedPublicIp: assignedPublicIpStr,
      publicIpOffset: publicIpOffset,
      blockIndexOnIp: blockIndexOnIp,
      portRange: `${startPort} - ${endPort}`,
      startPort: startPort,
      endPort: endPort,
      portBlockSize: portBlockSize,
      subscribersPerPublicIp: subscribersPerPublicIp,
      totalPublicIps: totalPublicIps,
      maxSubscribersSupported: maxSubscribersSupported
    };
  }

  /**
   * RFC 7422 Deterministic CGNAT Reverse Mapping (Lawful Intercept):
   * Instantly calculates the subscriber IP from a given Public IP and Source Port in O(1) time without logs.
   */
  function calculateReverseMapping(params) {
    const publicIpStr = params.publicIp || '198.51.100.1';
    const port = parseInt(params.port, 10) || 1050;
    const subscriberBaseStr = params.subscriberBase || '100.64.0.0';
    const publicPoolStartStr = params.publicPoolStart || '198.51.100.1';
    const publicPoolEndStr = params.publicPoolEnd || '198.51.100.64';
    const portBlockSize = Math.max(64, Math.min(8192, parseInt(params.portBlockSize, 10) || 1024));
    const portStart = Math.max(1024, parseInt(params.portStart, 10) || MIN_PORT);
    const portEnd = Math.min(65535, parseInt(params.portEnd, 10) || MAX_PORT);

    const availablePortsPerIp = (portEnd - portStart + 1);
    const subscribersPerPublicIp = Math.floor(availablePortsPerIp / portBlockSize);

    const pubInt = ipv4ToInt(publicIpStr);
    const pubStartInt = ipv4ToInt(publicPoolStartStr);
    const pubEndInt = ipv4ToInt(publicPoolEndStr);
    const subBaseInt = ipv4ToInt(subscriberBaseStr);

    if (pubInt < pubStartInt || pubInt > pubEndInt) {
      return {
        success: false,
        error: `Public IP ${publicIpStr} does not belong to the configured CGNAT pool (${publicPoolStartStr} - ${publicPoolEndStr}).`
      };
    }

    if (port < portStart || port > portEnd) {
      return {
        success: false,
        error: `Port ${port} is outside the deterministic port allocation window (${portStart} - ${portEnd}).`
      };
    }

    const publicIpOffset = pubInt - pubStartInt;
    const blockIndexOnIp = Math.floor((port - portStart) / portBlockSize);
    const subscriberIndex = (publicIpOffset * subscribersPerPublicIp) + blockIndexOnIp;
    const subscriberIpInt = subBaseInt + subscriberIndex;
    const subscriberIpStr = intToIpv4(subscriberIpInt);

    return {
      success: true,
      observedPublicIp: publicIpStr,
      observedPort: port,
      identifiedSubscriberIp: subscriberIpStr,
      subscriberIndex: subscriberIndex,
      blockRange: `${portStart + (blockIndexOnIp * portBlockSize)} - ${portStart + ((blockIndexOnIp + 1) * portBlockSize) - 1}`
    };
  }

  /**
   * RFC 6052 / RFC 6146 NAT64 IPv4-Embedded IPv6 Address Synthesis:
   * Encodes an IPv4 address (e.g. 8.8.8.8) into the Well-Known Prefix (64:ff9b::/96)
   */
  function synthesizeNat64Address(ipv4Str, prefix) {
    const pfx = (prefix || '64:ff9b::/96').replace('/96', '').trim();
    const parts = (ipv4Str || '8.8.8.8').trim().split('.').map(Number);
    if (parts.length !== 4) return '64:ff9b::0808:0808';

    const hex1 = ((parts[0] << 8) | parts[1]).toString(16).padStart(4, '0');
    const hex2 = ((parts[2] << 8) | parts[3]).toString(16).padStart(4, '0');

    if (pfx.endsWith('::')) {
      return `${pfx}${hex1}:${hex2}`;
    }
    return `${pfx}:${hex1}:${hex2}`;
  }

  /**
   * Forges an Ethernet II + IPv4/TCP translated packet with calculated checksums & FCS
   */
  function forgeCgnatPacket(params) {
    const p = params || {};
    const srcMac = parseMac(p.srcMac || '00:1a:2b:3c:4d:5e');
    const dstMac = parseMac(p.dstMac || '00:50:56:a1:b2:c3');

    const isNat64 = Boolean(p.isNat64);
    const srcIp = p.srcIp || (isNat64 ? '198.51.100.1' : '198.51.100.1');
    const dstIp = p.dstIp || '8.8.8.8';
    const srcPort = parseInt(p.srcPort, 10) || 1050;
    const dstPort = parseInt(p.dstPort, 10) || 443;

    const ethHeader = [
      ...dstMac,
      ...srcMac,
      0x08, 0x00 // EtherType IPv4
    ];

    const srcParts = srcIp.split('.').map(Number);
    const dstParts = dstIp.split('.').map(Number);

    // IPv4 Header (20 bytes)
    const ipHeaderWithoutCksum = [
      0x45, 0x00, 0x00, 0x28, // Ver 4, IHL 5, Total Len 40B (20B IP + 20B TCP)
      0x1c, 0x2d, 0x40, 0x00, // ID, Flags (DF=1)
      0x40, 0x06, 0x00, 0x00, // TTL 64, Protocol TCP (6), Checksum (placeholder)
      ...srcParts,
      ...dstParts
    ];

    const ipCksum = calculateIpChecksum(ipHeaderWithoutCksum);
    ipHeaderWithoutCksum[10] = (ipCksum >> 8) & 0xff;
    ipHeaderWithoutCksum[11] = ipCksum & 0xff;

    // TCP Header (20 bytes, SYN packet)
    const tcpHeaderWithoutCksum = [
      (srcPort >> 8) & 0xff, srcPort & 0xff,
      (dstPort >> 8) & 0xff, dstPort & 0xff,
      0x10, 0x20, 0x30, 0x40, // Seq Number
      0x00, 0x00, 0x00, 0x00, // Ack Number
      0x50, 0x02, 0x72, 0x10, // Data Offset 5 (20B), Flags (SYN), Window 29200
      0x00, 0x00, 0x00, 0x00  // Checksum placeholder, Urgent pointer 0
    ];

    // TCP Pseudo-Header Checksum
    const tcpPseudoHeader = [
      ...srcParts,
      ...dstParts,
      0x00, 0x06, // Zero, Protocol TCP
      0x00, 0x14  // TCP Length 20 bytes
    ];

    const tcpCheckBytes = tcpPseudoHeader.concat(tcpHeaderWithoutCksum);
    const tcpCksum = calculateIpChecksum(tcpCheckBytes);
    tcpHeaderWithoutCksum[16] = (tcpCksum >> 8) & 0xff;
    tcpHeaderWithoutCksum[17] = tcpCksum & 0xff;

    const frameWithoutFcs = ethHeader.concat(ipHeaderWithoutCksum).concat(tcpHeaderWithoutCksum);

    // Padding to 60 bytes minimum payload
    while (frameWithoutFcs.length < 60) {
      frameWithoutFcs.push(0x00);
    }

    const crc = calculateCrc32(frameWithoutFcs);
    const fcs = [
      crc & 0xff,
      (crc >> 8) & 0xff,
      (crc >> 16) & 0xff,
      (crc >> 24) & 0xff
    ];

    const rawBytes = frameWithoutFcs.concat(fcs);

    return {
      rawBytes: rawBytes,
      totalLength: rawBytes.length,
      srcMac: formatMac(srcMac),
      dstMac: formatMac(dstMac),
      srcIp: srcIp,
      dstIp: dstIp,
      srcPort: srcPort,
      dstPort: dstPort,
      isNat64: isNat64,
      ipChecksumHex: '0x' + ipCksum.toString(16).padStart(4, '0'),
      tcpChecksumHex: '0x' + tcpCksum.toString(16).padStart(4, '0'),
      crc32Hex: '0x' + crc.toString(16).padStart(8, '0')
    };
  }

  function formatHexDump(rawBytes) {
    if (!rawBytes || !rawBytes.length) return '';
    const lines = [];

    for (let i = 0; i < rawBytes.length; i += 16) {
      const chunk = rawBytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');

      let hexPart1 = '';
      for (let j = 0; j < 8; j++) {
        if (j < chunk.length) {
          hexPart1 += chunk[j].toString(16).padStart(2, '0') + ' ';
        } else {
          hexPart1 += '   ';
        }
      }

      let hexPart2 = '';
      for (let j = 8; j < 16; j++) {
        if (j < chunk.length) {
          hexPart2 += chunk[j].toString(16).padStart(2, '0') + ' ';
        } else {
          hexPart2 += '   ';
        }
      }

      const hexPart = (hexPart1 + ' ' + hexPart2).trimEnd();

      let asciiPart = '';
      for (let j = 0; j < chunk.length; j++) {
        const b = chunk[j];
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      }

      lines.push(`${offset}   ${hexPart.padEnd(48, ' ')}   |${asciiPart}|`);
    }

    return lines.join('\n');
  }

  function generatePcap(frameObj) {
    const rawBytes = frameObj.rawBytes;
    const pcapHeader = new Uint8Array(24);
    const pcapView = new DataView(pcapHeader.buffer);

    pcapView.setUint32(0, 0xa1b2c3d4, true); // Magic Number (Microsecond, Little-Endian)
    pcapView.setUint16(4, 2, true);          // Major Version 2
    pcapView.setUint16(6, 4, true);          // Minor Version 4
    pcapView.setInt32(8, 0, true);           // GMT offset (0)
    pcapView.setUint32(12, 0, true);         // Accuracy (0)
    pcapView.setUint32(16, 262144, true);    // Snapshot length (256KB)
    pcapView.setUint32(20, 1, true);         // Link Type: Ethernet (1)

    const nowMs = Date.now();
    const sec = Math.floor(nowMs / 1000);
    const usec = (nowMs % 1000) * 1000;

    const recordHeader = new Uint8Array(16);
    const recordView = new DataView(recordHeader.buffer);
    recordView.setUint32(0, sec, true);
    recordView.setUint32(4, usec, true);
    recordView.setUint32(8, rawBytes.length, true);
    recordView.setUint32(12, rawBytes.length, true);

    const fullPcap = new Uint8Array(24 + 16 + rawBytes.length);
    fullPcap.set(pcapHeader, 0);
    fullPcap.set(recordHeader, 24);
    fullPcap.set(new Uint8Array(rawBytes), 40);

    return fullPcap;
  }

  /**
   * Simulates Subscriber Session Concurrency & Port Quota Exhaustion
   */
  function simulatePortExhaustion(params) {
    const quota = Math.max(64, parseInt(params.portQuota, 10) || 1024);
    const activeSessions = Math.max(0, parseInt(params.activeSessions, 10) || 500);
    const requestedNewSessions = Math.max(1, parseInt(params.newSessionsRequested, 10) || 50);

    const totalRequested = activeSessions + requestedNewSessions;
    const memoryPerSessionBytes = 256; // Typical CGNAT hardware TCAM/RAM footprint
    const totalMemoryKb = (activeSessions * memoryPerSessionBytes) / 1024;

    if (totalRequested > quota) {
      const allowed = Math.max(0, quota - activeSessions);
      const dropped = requestedNewSessions - allowed;
      return {
        exhausted: true,
        riskLevel: 'CRITICAL',
        status: 'PORT_QUOTA_EXHAUSTED',
        title: 'CRITICAL OUTAGE: Subscriber Port Quota Saturated',
        summary: `Subscriber has ${activeSessions} active sessions. Requested ${requestedNewSessions} new sockets, exceeding quota of ${quota}. ${dropped} connections dropped!`,
        activeSessions: activeSessions,
        allowedSessions: allowed,
        droppedSessions: dropped,
        utilizationPct: Math.min(100, Math.round((activeSessions / quota) * 100)),
        memoryUsedKb: totalMemoryKb.toFixed(2),
        remediation: 'Configure port-preservation, TCP timeout reduction (RFC 5382: 2hr default -> 10m idle), or increase block quota.'
      };
    }

    return {
      exhausted: false,
      riskLevel: 'PROTECTED',
      status: 'WITHIN_QUOTA_LIMITS',
      title: 'PROTECTED: Subscriber Well Within Port Allocation Quota',
      summary: `Subscriber has ${totalRequested} / ${quota} ports utilized (${Math.round((totalRequested / quota) * 100)}%). All sessions successfully established.`,
      activeSessions: totalRequested,
      allowedSessions: requestedNewSessions,
      droppedSessions: 0,
      utilizationPct: Math.round((totalRequested / quota) * 100),
      memoryUsedKb: ((totalRequested * memoryPerSessionBytes) / 1024).toFixed(2),
      remediation: 'Compliant. No connection drops or subscriber packet blackholing.'
    };
  }

  return {
    RFC6598_PREFIX,
    NAT64_WELL_KNOWN_PREFIX,
    ipv4ToInt,
    intToIpv4,
    parseMac,
    formatMac,
    calculateCrc32,
    calculateIpChecksum,
    calculateDeterministicMapping,
    calculateReverseMapping,
    synthesizeNat64Address,
    forgeCgnatPacket,
    formatHexDump,
    generatePcap,
    simulatePortExhaustion
  };
}));
