/**
 * CGNATForge Pro - Web Studio Controller & Preset Manager
 */

(function () {
  'use strict';

  const PRESETS = {
    'tier1-carrier': {
      subscriberSubnet: '100.64.0.0/10',
      publicPoolStart: '198.51.100.1',
      publicPoolEnd: '198.51.100.64',
      portQuota: 1024,
      testSubscriber: '100.64.1.50',
      natMode: 'deterministic',
      deterministicEnabled: true,
      nat64Enabled: true,
      hairpinningEnabled: true,
      eimEnabled: true,
      tcpIdleTimeoutSec: 1800,
      udpIdleTimeoutSec: 120,
      virtualReassemblyEnabled: true,
      tcpMssClamping: 1412,
      urpfEnabled: true,
      highSpeedLoggingEnabled: true,
      activeSessions: 650,
      newSessionsRequested: 100
    },
    'telco-5g-nat64': {
      subscriberSubnet: '100.64.0.0/10',
      publicPoolStart: '198.51.100.1',
      publicPoolEnd: '198.51.100.32',
      portQuota: 2048,
      testSubscriber: '100.64.2.10',
      natMode: 'nat64',
      deterministicEnabled: true,
      nat64Enabled: true,
      hairpinningEnabled: true,
      eimEnabled: true,
      tcpIdleTimeoutSec: 1800,
      udpIdleTimeoutSec: 120,
      virtualReassemblyEnabled: true,
      tcpMssClamping: 1360,
      urpfEnabled: true,
      highSpeedLoggingEnabled: true,
      activeSessions: 800,
      newSessionsRequested: 200
    },
    'vulnerable-dynamic': {
      subscriberSubnet: '10.0.0.0/8',
      publicPoolStart: '198.51.100.1',
      publicPoolEnd: '198.51.100.4',
      portQuota: 4096,
      testSubscriber: '10.1.1.50',
      natMode: 'dynamic',
      deterministicEnabled: false,
      nat64Enabled: false,
      hairpinningEnabled: false,
      eimEnabled: false,
      tcpIdleTimeoutSec: 7200,
      udpIdleTimeoutSec: 600,
      virtualReassemblyEnabled: false,
      tcpMssClamping: 1500,
      urpfEnabled: false,
      highSpeedLoggingEnabled: false,
      activeSessions: 3900,
      newSessionsRequested: 300
    }
  };

  let currentConfig = Object.assign({}, PRESETS['tier1-carrier']);
  let activeTab = 'cisco-ios';
  let forgedPacketCache = null;

  // DOM Elements
  const inputSubscriberSubnet = document.getElementById('input-subscriber-subnet');
  const selectNatMode = document.getElementById('select-nat-mode');
  const inputPublicStart = document.getElementById('input-public-start');
  const inputPublicEnd = document.getElementById('input-public-end');
  const inputPortQuota = document.getElementById('input-port-quota');
  const inputTestSubscriber = document.getElementById('input-test-subscriber');
  const badgeFrameLen = document.getElementById('badge-frame-len');

  const badgeMappingStatus = document.getElementById('badge-mapping-status');
  const mappingDiagBanner = document.getElementById('mapping-diag-banner');
  const mappingDiagTitle = document.getElementById('mapping-diag-title');
  const mappingDiagDesc = document.getElementById('mapping-diag-desc');

  const inputRevIp = document.getElementById('input-rev-ip');
  const inputRevPort = document.getElementById('input-rev-port');
  const reverseResultText = document.getElementById('reverse-result-text');

  const inputActiveSessions = document.getElementById('input-active-sessions');
  const inputNewSessions = document.getElementById('input-new-sessions');
  const badgeQuotaStatus = document.getElementById('badge-quota-status');
  const quotaDiagBanner = document.getElementById('quota-diag-banner');
  const quotaDiagTitle = document.getElementById('quota-diag-title');
  const quotaDiagDesc = document.getElementById('quota-diag-desc');

  const auditGradeCircle = document.getElementById('audit-grade-circle');
  const auditScoreText = document.getElementById('audit-score-text');
  const auditComplianceText = document.getElementById('audit-compliance-text');
  const auditScoreBar = document.getElementById('audit-score-bar');
  const auditStatusBadge = document.getElementById('audit-status-badge');
  const findingsContainer = document.getElementById('findings-container');

  const hexDissectorBox = document.getElementById('hex-dissector-box');
  const synthesizerOutputBox = document.getElementById('synthesizer-output-box');

  const btnCopyHex = document.getElementById('btn-copy-hex');
  const btnDownloadPcap = document.getElementById('btn-download-pcap');
  const btnCopyConfig = document.getElementById('btn-copy-config');
  const presetButtons = document.querySelectorAll('.btn-preset');
  const tabButtons = document.querySelectorAll('.tab-btn');

  function updateUiFromConfig() {
    inputSubscriberSubnet.value = currentConfig.subscriberSubnet;
    selectNatMode.value = currentConfig.natMode;
    inputPublicStart.value = currentConfig.publicPoolStart;
    inputPublicEnd.value = currentConfig.publicPoolEnd;
    inputPortQuota.value = currentConfig.portQuota;
    inputTestSubscriber.value = currentConfig.testSubscriber;

    inputActiveSessions.value = currentConfig.activeSessions;
    inputNewSessions.value = currentConfig.newSessionsRequested;

    recomputeAll();
  }

  function readConfigFromUi() {
    currentConfig.subscriberSubnet = inputSubscriberSubnet.value.trim();
    currentConfig.natMode = selectNatMode.value;
    currentConfig.deterministicEnabled = (currentConfig.natMode === 'deterministic' || currentConfig.natMode === 'nat64');
    currentConfig.nat64Enabled = (currentConfig.natMode === 'nat64');

    currentConfig.publicPoolStart = inputPublicStart.value.trim();
    currentConfig.publicPoolEnd = inputPublicEnd.value.trim();
    currentConfig.portQuota = parseInt(inputPortQuota.value, 10) || 1024;
    currentConfig.testSubscriber = inputTestSubscriber.value.trim();

    currentConfig.activeSessions = parseInt(inputActiveSessions.value, 10) || 0;
    currentConfig.newSessionsRequested = parseInt(inputNewSessions.value, 10) || 1;

    recomputeAll();
  }

  function recomputeAll() {
    // 1. Calculate Deterministic Mapping
    const fwdMap = CgnatProtocolEngine.calculateDeterministicMapping({
      subscriberIp: currentConfig.testSubscriber,
      subscriberBase: currentConfig.subscriberSubnet.split('/')[0],
      publicPoolStart: currentConfig.publicPoolStart,
      publicPoolEnd: currentConfig.publicPoolEnd,
      portBlockSize: currentConfig.portQuota
    });

    if (fwdMap.success) {
      badgeMappingStatus.textContent = currentConfig.deterministicEnabled ? 'DETERMINISTIC' : 'DYNAMIC PAT';
      badgeMappingStatus.className = 'badge badge-emerald';
      mappingDiagBanner.className = 'diag-banner diag-protected';
      mappingDiagTitle.textContent = `FORWARD MAPPING: ${fwdMap.subscriberIp} Assigned`;
      mappingDiagDesc.textContent = `Translated to Public IP ${fwdMap.assignedPublicIp} | Port Block: ${fwdMap.portRange} (${fwdMap.subscribersPerPublicIp} subs/IP).`;

      // Update reverse test inputs if default
      if (document.activeElement !== inputRevIp && document.activeElement !== inputRevPort) {
        inputRevIp.value = fwdMap.assignedPublicIp;
        inputRevPort.value = fwdMap.startPort + 50;
      }
    } else {
      badgeMappingStatus.textContent = 'MAPPING ERROR';
      badgeMappingStatus.className = 'badge badge-rose';
      mappingDiagBanner.className = 'diag-banner diag-critical';
      mappingDiagTitle.textContent = 'MAPPING OVERFLOW';
      mappingDiagDesc.textContent = fwdMap.error;
    }

    // 2. Calculate Reverse Lawful Intercept Lookup
    const revMap = CgnatProtocolEngine.calculateReverseMapping({
      publicIp: inputRevIp.value.trim(),
      port: parseInt(inputRevPort.value, 10) || 1024,
      subscriberBase: currentConfig.subscriberSubnet.split('/')[0],
      publicPoolStart: currentConfig.publicPoolStart,
      publicPoolEnd: currentConfig.publicPoolEnd,
      portBlockSize: currentConfig.portQuota
    });

    if (revMap.success) {
      reverseResultText.textContent = `${revMap.identifiedSubscriberIp} [O(1) NO LOGS REQUIRED]`;
      reverseResultText.style.color = 'var(--primary-emerald)';
    } else {
      reverseResultText.textContent = `[Lookup Failed: ${revMap.error}]`;
      reverseResultText.style.color = 'var(--primary-rose)';
    }

    // 3. Port Quota Exhaustion Simulation
    const exhSim = CgnatProtocolEngine.simulatePortExhaustion({
      portQuota: currentConfig.portQuota,
      activeSessions: currentConfig.activeSessions,
      newSessionsRequested: currentConfig.newSessionsRequested
    });

    quotaDiagTitle.textContent = exhSim.title;
    quotaDiagDesc.textContent = exhSim.summary;

    if (exhSim.exhausted) {
      badgeQuotaStatus.textContent = 'EXHAUSTED';
      badgeQuotaStatus.className = 'badge badge-rose';
      quotaDiagBanner.className = 'diag-banner diag-critical';
    } else {
      badgeQuotaStatus.textContent = 'NORMAL';
      badgeQuotaStatus.className = 'badge badge-emerald';
      quotaDiagBanner.className = 'diag-banner diag-protected';
    }

    // 4. Forge Packet & Hex Dissector
    forgedPacketCache = CgnatProtocolEngine.forgeCgnatPacket({
      srcIp: fwdMap.assignedPublicIp || currentConfig.publicPoolStart,
      dstIp: '8.8.8.8',
      srcPort: fwdMap.startPort || 1050,
      dstPort: 443,
      isNat64: currentConfig.nat64Enabled
    });

    badgeFrameLen.textContent = `FRAME: ${forgedPacketCache.totalLength}B`;
    hexDissectorBox.textContent = CgnatProtocolEngine.formatHexDump(forgedPacketCache.rawBytes);

    // 5. 10-Point Zero-Trust CGNAT Audit
    const audit = CgnatSecurityAuditor.auditConfiguration({
      subscriberSubnet: currentConfig.subscriberSubnet,
      deterministicEnabled: currentConfig.deterministicEnabled,
      portQuota: currentConfig.portQuota,
      hairpinningEnabled: currentConfig.hairpinningEnabled,
      eimEnabled: currentConfig.eimEnabled,
      tcpIdleTimeoutSec: currentConfig.tcpIdleTimeoutSec,
      udpIdleTimeoutSec: currentConfig.udpIdleTimeoutSec,
      virtualReassemblyEnabled: currentConfig.virtualReassemblyEnabled,
      nat64Enabled: currentConfig.nat64Enabled,
      tcpMssClamping: currentConfig.tcpMssClamping,
      urpfEnabled: currentConfig.urpfEnabled,
      highSpeedLoggingEnabled: currentConfig.highSpeedLoggingEnabled
    });

    auditScoreText.textContent = `${audit.score} / 100 Points`;
    auditGradeCircle.textContent = audit.grade;
    auditGradeCircle.className = `grade-circle grade-${audit.grade.toLowerCase().replace('+', 'plus')}`;
    auditScoreBar.style.width = `${audit.score}%`;

    if (audit.passed) {
      auditScoreBar.style.background = 'var(--primary-emerald)';
      auditComplianceText.textContent = 'Zero-Trust Hardened';
      auditComplianceText.style.color = 'var(--primary-emerald)';
      auditStatusBadge.textContent = 'PASSING';
      auditStatusBadge.className = 'badge badge-emerald';
    } else {
      auditScoreBar.style.background = 'var(--primary-rose)';
      auditComplianceText.textContent = 'Non-Compliant / Audit Failure';
      auditComplianceText.style.color = 'var(--primary-rose)';
      auditStatusBadge.textContent = 'CRITICAL FAILS';
      auditStatusBadge.className = 'badge badge-rose';
    }

    // Render findings
    findingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = `finding-item ${f.level.toLowerCase()}`;
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 0.2rem;">
          <span>[${f.level}] ${f.id} - ${f.title}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxPoints} pts</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.78rem;">${f.finding}</div>
      `;
      findingsContainer.appendChild(div);
    });

    // 6. Update Synthesizer Output
    renderSynthesizerConfig();
  }

  function renderSynthesizerConfig() {
    const synthParams = {
      subscriberSubnet: currentConfig.subscriberSubnet || '100.64.0.0/10',
      publicPoolStart: currentConfig.publicPoolStart || '198.51.100.1',
      publicPoolEnd: currentConfig.publicPoolEnd || '198.51.100.64',
      portQuota: currentConfig.portQuota || 1024,
      deterministicEnabled: currentConfig.deterministicEnabled,
      nat64Enabled: currentConfig.nat64Enabled,
      tcpMssClamping: currentConfig.tcpMssClamping || 1412
    };

    let text = '';
    if (activeTab === 'cisco-ios') {
      text = CgnatConfigSynthesizer.synthesizeCiscoIosXe(synthParams);
    } else if (activeTab === 'cisco-nxos') {
      text = CgnatConfigSynthesizer.synthesizeCiscoIosXr(synthParams);
    } else if (activeTab === 'juniper') {
      text = CgnatConfigSynthesizer.synthesizeJunos(synthParams);
    } else if (activeTab === 'linux') {
      text = CgnatConfigSynthesizer.synthesizeLinux(synthParams);
    } else if (activeTab === 'a10') {
      text = CgnatConfigSynthesizer.synthesizeA10Thunder(synthParams);
    }
    synthesizerOutputBox.textContent = text;
  }

  // Event Listeners
  [inputSubscriberSubnet, selectNatMode, inputPublicStart, inputPublicEnd,
   inputPortQuota, inputTestSubscriber, inputActiveSessions, inputNewSessions,
   inputRevIp, inputRevPort].forEach(el => {
    el.addEventListener('change', readConfigFromUi);
    el.addEventListener('input', readConfigFromUi);
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        currentConfig = Object.assign({}, PRESETS[presetKey]);
        updateUiFromConfig();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.getAttribute('data-tab');
      renderSynthesizerConfig();
    });
  });

  btnCopyHex.addEventListener('click', () => {
    navigator.clipboard.writeText(hexDissectorBox.textContent).then(() => {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(() => btnCopyHex.textContent = 'Copy Hex', 2000);
    });
  });

  btnCopyConfig.addEventListener('click', () => {
    navigator.clipboard.writeText(synthesizerOutputBox.textContent).then(() => {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(() => btnCopyConfig.textContent = 'Copy Config', 2000);
    });
  });

  btnDownloadPcap.addEventListener('click', () => {
    if (!forgedPacketCache) return;
    const pcapBytes = CgnatProtocolEngine.generatePcap(forgedPacketCache);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cgnat-packet-${currentConfig.natMode}-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Initial load
  updateUiFromConfig();
})();
