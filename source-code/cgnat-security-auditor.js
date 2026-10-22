/**
 * CGNATForge Pro - 10-Point Zero-Trust Carrier-Grade NAT & NAT64 Security Auditor
 * 
 * Evaluates carrier and enterprise NAT configurations against IETF RFC 6888, RFC 6598,
 * RFC 7422, RFC 4787, RFC 5382, and CALEA / Lawful Intercept standards.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CgnatSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_CONTROLS = [
    {
      id: 'CGN-SEC-01',
      title: 'RFC 6598 Shared Address Space Allocation (100.64.0.0/10)',
      maxPoints: 15,
      evaluate: function (cfg) {
        const subSubnet = (cfg.subscriberSubnet || '100.64.0.0/10').trim();
        if (subSubnet.startsWith('100.64.') || subSubnet.startsWith('100.65.') || subSubnet.startsWith('100.127.')) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: `Subscriber pool correctly allocated within RFC 6598 Shared Address Space (${subSubnet}).`,
            remediation: 'Compliant. Avoids address collisions with enterprise RFC 1918 private subnets.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: `NON-COMPLIANT SUBNET: Carrier NAT uses ${subSubnet} instead of RFC 6598 (100.64.0.0/10). High risk of route collisions with enterprise customers using 10.0.0.0/8 or 192.168.0.0/16.`,
          remediation: 'Re-address internal subscriber CGNAT pool to RFC 6598 Shared Address Space (100.64.0.0/10).'
        };
      }
    },
    {
      id: 'CGN-SEC-02',
      title: 'RFC 7422 Deterministic Port Batching & Lawful Intercept',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.deterministicEnabled) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'RFC 7422 Deterministic Port Allocation enabled. Subscribers algorithmically mapped to fixed port blocks.',
            remediation: 'Compliant. Instant O(1) Lawful Intercept reverse lookup without storing terabytes of per-session translation logs.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'FAIL',
          finding: 'CRITICAL AUDIT RISK: Non-deterministic Dynamic PAT in use. Subpoena / Lawful Intercept compliance requires logging every single connection, overloading syslog servers and risking regulatory non-compliance.',
          remediation: 'Migrate to RFC 7422 Deterministic Port Batching (e.g. 1024 or 2048 ports per subscriber).'
        };
      }
    },
    {
      id: 'CGN-SEC-03',
      title: 'Subscriber Port Quota Enforcement (DoS Mitigation)',
      maxPoints: 12,
      evaluate: function (cfg) {
        const quota = parseInt(cfg.portQuota, 10) || 1024;
        if (quota >= 512 && quota <= 2048) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: `Strict subscriber port quota enforced (${quota} ports per host). Prevents pool exhaustion.`,
            remediation: 'Compliant. Single compromised botnet or P2P torrent client cannot starve fellow subscribers.'
          };
        } else if (quota > 2048) {
          return {
            passed: false,
            score: 6,
            level: 'WARN',
            finding: `High port quota (${quota} ports). Reduces subscriber density per public IP and increases exhaustion risk during spikes.`,
            remediation: 'Recommend standardizing on 1024 to 2048 ports per subscriber.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: `Low port quota (${quota} ports). Legitimate heavy browser usage or gaming will experience dropped sockets.`,
          remediation: 'Increase minimum quota to at least 512 or 1024 ports per subscriber.'
        };
      }
    },
    {
      id: 'CGN-SEC-04',
      title: 'Endpoint-Independent Mapping (EIM) & Hairpinning Support',
      maxPoints: 12,
      evaluate: function (cfg) {
        if (cfg.hairpinningEnabled && cfg.eimEnabled) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'RFC 4787 / RFC 5382 Endpoint-Independent Mapping (EIM) and Hairpinning active.',
            remediation: 'Compliant. P2P communications, WebRTC video calling, and online multiplayer gaming function seamlessly between internal subscribers.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Symmetric NAT / Hairpinning disabled. Internal subscribers cannot connect directly to each other, breaking WebRTC and gaming.',
          remediation: 'Enable endpoint-independent mapping and hairpinning on the CGNAT translation profile.'
        };
      }
    },
    {
      id: 'CGN-SEC-05',
      title: 'State Timeout Tuning (TCP / UDP Stale Session Defense)',
      maxPoints: 10,
      evaluate: function (cfg) {
        const tcpTimeout = parseInt(cfg.tcpIdleTimeoutSec, 10) || 1800;
        const udpTimeout = parseInt(cfg.udpIdleTimeoutSec, 10) || 120;
        if (tcpTimeout <= 3600 && udpTimeout <= 300) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `Optimized state timeouts (TCP: ${tcpTimeout}s, UDP: ${udpTimeout}s). Stale sessions purged promptly.`,
            remediation: 'Compliant. Prevents translation table exhaustion caused by dead sockets.'
          };
        }
        return {
          passed: false,
          score: 4,
          level: 'WARN',
          finding: `Overly long idle timeouts (TCP: ${tcpTimeout}s, UDP: ${udpTimeout}s). Stale sessions hold ports indefinitely.`,
          remediation: 'Configure aggressive idle timeouts: TCP Idle <= 1800s, UDP Idle <= 120s, TCP Reset <= 30s.'
        };
      }
    },
    {
      id: 'CGN-SEC-06',
      title: 'IP Fragment Assembly & Virtual Reassembly Protection',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.virtualReassemblyEnabled) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Hardware Virtual Packet Reassembly (VPR) enabled. Inspects fragments before translation.',
            remediation: 'Compliant. Protects against Tiny Fragment, Out-of-Order Overlap, and Teardrop evasion attacks.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL SECURITY DEFICIENCY: IP fragment reassembly disabled. Attackers can smuggle malicious payloads past CGNAT filters using fragmented packets.',
          remediation: 'Enable virtual reassembly: "ip virtual-reassembly in" or platform equivalent.'
        };
      }
    },
    {
      id: 'CGN-SEC-07',
      title: 'RFC 6146 / RFC 6052 Stateful NAT64 & DNS64 Integration',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.nat64Enabled) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'Stateful NAT64 enabled using Well-Known Prefix (64:ff9b::/96). Supports IPv6-only transition.',
            remediation: 'Compliant. IPv6-only subscribers can access IPv4-only public internet destinations.'
          };
        }
        return {
          passed: false,
          score: 3,
          level: 'INFO',
          finding: 'NAT64 disabled: Gateway operates exclusively in dual-stack IPv4-IPv4 CGNAT mode.',
          remediation: 'Enable stateful NAT64 to facilitate 5G and IPv6-only subscriber migration.'
        };
      }
    },
    {
      id: 'CGN-SEC-08',
      title: 'TCP MSS Clamping Protection (PMTU Blackhole Shield)',
      maxPoints: 8,
      evaluate: function (cfg) {
        const mss = parseInt(cfg.tcpMssClamping, 10) || 1412;
        if (mss >= 1360 && mss <= 1452) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: `TCP MSS clamping enforced at ${mss} bytes. Prevents PMTU discovery blackholes.`,
            remediation: 'Compliant. Overcomes encapsulation overhead across mobile, broadband, and VPN tunnels.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'TCP MSS clamping disabled or misconfigured. Packets exceeding PMTU without ICMP Unreachable will hang.',
          remediation: 'Apply "ip tcp adjust-mss 1412" or "1360" on subscriber-facing interfaces.'
        };
      }
    },
    {
      id: 'CGN-SEC-09',
      title: 'Anti-Spoofing Unicast RPF (uRPF) Ingress Enforcement',
      maxPoints: 5,
      evaluate: function (cfg) {
        if (cfg.urpfEnabled) {
          return {
            passed: true,
            score: 5,
            level: 'PASS',
            finding: 'Unicast Reverse Path Forwarding (uRPF Strict/Loose) active on subscriber ingress.',
            remediation: 'Compliant. Prevents spoofed IP source packets from entering the CGNAT translation pipeline.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'uRPF disabled on subscriber ingress interfaces. Injected spoofed traffic can pollute translation tables.',
          remediation: 'Enable "ip verify unicast source reachable-via rx" on subscriber interfaces.'
        };
      }
    },
    {
      id: 'CGN-SEC-10',
      title: 'NetFlow v9 / IPFIX High-Speed Logging (HSL) Throttling',
      maxPoints: 5,
      evaluate: function (cfg) {
        if (cfg.highSpeedLoggingEnabled) {
          return {
            passed: true,
            score: 5,
            level: 'PASS',
            finding: 'High-Speed Logging (HSL) configured via IPFIX/NetFlow v9 over UDP to dedicated collectors.',
            remediation: 'Compliant. Prevents switch control plane CPU exhaustion during connection burst storms.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'INFO',
          finding: 'Standard syslog used for NAT logging. May drop records or lock router consoles under high session churn.',
          remediation: 'Configure NetFlow v9 or IPFIX High-Speed Logging to offload logging to hardware ASIC.'
        };
      }
    }
  ];

  function auditConfiguration(cfg) {
    let totalScore = 0;
    const findings = [];

    AUDIT_CONTROLS.forEach(ctrl => {
      const res = ctrl.evaluate(cfg);
      totalScore += res.score;
      findings.push({
        id: ctrl.id,
        title: ctrl.title,
        maxPoints: ctrl.maxPoints,
        score: res.score,
        level: res.level,
        passed: res.passed,
        finding: res.finding,
        remediation: res.remediation
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 60) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      passed: totalScore >= 80,
      findings: findings,
      evaluatedAt: new Date().toISOString()
    };
  }

  return {
    AUDIT_CONTROLS,
    auditConfiguration
  };
}));
