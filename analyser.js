/* ================================================================
   Cybthreat — Email Header Analyser
   analyser.js — All parsing, upload, and rendering logic
   ================================================================ */

/* ─── File Upload & Drag-Drop ─────────────────────────────────────── */
function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  readEMLFile(file);
  event.target.value = ''; // reset so same file can be re-selected
}

function readEMLFile(file) {
  const validTypes = ['.eml', '.txt', '.msg'];
  const isValid = validTypes.some(ext => file.name.toLowerCase().endsWith(ext));
  if (!isValid) {
    alert('Please select a .eml, .txt, or .msg file.');
    return;
  }

  const reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById('emlInput').value = e.target.result;
    showFileLoadedBadge(file.name);
    analyseEML();
  };
  reader.onerror = function() {
    alert('Failed to read the file. Please try again.');
  };
  reader.readAsText(file, 'UTF-8');
}

function showFileLoadedBadge(filename) {
  const hint = document.getElementById('inputHint');
  if (hint) {
    hint.innerHTML = `<span class="file-loaded-badge">
      <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
        <path d="M3 8l4 4 6-6" stroke="currentColor" stroke-width="1.8"
          stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      ${escapeHtml(filename)}
    </span>`;
  }
}

function resetInputHint() {
  const hint = document.getElementById('inputHint');
  if (hint) {
    hint.innerHTML = `<svg width="12" height="12" viewBox="0 0 16 16" fill="none">
      <rect x="2" y="4" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.2"/>
      <path d="M5 4V3a3 3 0 016 0v1" stroke="currentColor" stroke-width="1.2"/>
    </svg>
    All analysis is done client-side — no data is sent anywhere`;
  }
}

/* ─── DOMContentLoaded: drag-drop init ───────────────────────────── */
document.addEventListener('DOMContentLoaded', function () {
  const dropZone = document.getElementById('dropZone');

  /* Drag over entire window → highlight drop zone */
  ['dragenter', 'dragover'].forEach(evt => {
    document.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(evt => {
    document.addEventListener(evt, e => {
      dropZone.classList.remove('drag-over');
    });
  });

  document.addEventListener('drop', function (e) {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;
    readEMLFile(file);
  });

  /* Click on drop zone → open file picker */
  dropZone.addEventListener('click', function () {
    document.getElementById('emlFileInput').click();
  });
});

/* ─── Header Parser ──────────────────────────────────────────────── */
function parseHeaders(raw) {
  const headers = {};
  const unfolded = raw
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n[ \t]+/g, ' ');

  for (const line of unfolded.split('\n')) {
    const m = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (!headers[key]) {
      headers[key] = val;
    } else if (Array.isArray(headers[key])) {
      headers[key].push(val);
    } else {
      headers[key] = [headers[key], val];
    }
  }
  return headers;
}

function getAll(h, key) {
  const v = h[key.toLowerCase()];
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}
function get(h, key) { return getAll(h, key)[0] || ''; }

/* ─── IP Utilities ───────────────────────────────────────────────── */
function extractIP(str) {
  const m = str.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return m ? (m[1] || m[2]) : '';
}

function isPrivateIP(ip) {
  if (!ip) return false;
  const p = ip.split('.').map(Number);
  return p[0] === 10 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    p[0] === 127;
}

/* ─── Auth Parser ────────────────────────────────────────────────── */
function parseAuthResults(str) {
  const res = { spf: 'none', dkim: 'none', dmarc: 'none', arc: 'none' };
  if (!str) return res;
  for (const c of ['spf', 'dkim', 'dmarc', 'arc']) {
    const m = str.match(new RegExp(c + '=([a-z]+)', 'i'));
    if (m) res[c] = m[1].toLowerCase();
  }
  return res;
}

/* ─── Received Header Parser ─────────────────────────────────────── */
function parseReceived(str) {
  const fromM = str.match(/from\s+([^\s(]+)/i);
  const byM   = str.match(/by\s+([^\s(]+)/i);
  const withM = str.match(/with\s+([^\s;]+)/i);
  const ip    = extractIP(str);
  const dateM = str.match(/;\s*(.+)$/);
  const d     = dateM ? new Date(dateM[1].trim()) : null;
  return {
    from:    fromM ? fromM[1] : '',
    by:      byM   ? byM[1]   : '',
    with:    withM ? withM[1] : '',
    ip:      ip,
    dateStr: dateM ? dateM[1].trim() : '',
    date:    (d && !isNaN(d)) ? d : null,
    raw:     str
  };
}

/* ─── Badge Helper ───────────────────────────────────────────────── */
function badge(val) {
  const v = (val || 'none').toLowerCase();
  if (['pass', 'ok', 'yes'].includes(v))
    return `<span class="badge badge-pass">✓ ${v}</span>`;
  if (['fail', 'reject', 'hardfail'].includes(v))
    return `<span class="badge badge-fail">✕ ${v}</span>`;
  if (['softfail', 'neutral', 'temperror', 'permerror', 'bestguesspass'].includes(v))
    return `<span class="badge badge-warn">⚠ ${v}</span>`;
  return `<span class="badge badge-none">— ${v}</span>`;
}

function escapeHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ─── Main Analyser ──────────────────────────────────────────────── */
function analyseEML() {
  const raw = document.getElementById('emlInput').value.trim();
  if (!raw) { alert('Please paste email headers or upload a .eml file first.'); return; }

  const h        = parseHeaders(raw);
  const findings = [];

  /* Envelope */
  const from       = get(h, 'from');
  const to         = get(h, 'to');
  const subject    = get(h, 'subject');
  const date       = get(h, 'date');
  const msgId      = get(h, 'message-id');
  const replyTo    = get(h, 'reply-to');
  const returnPath = get(h, 'return-path');
  const xMailer    = get(h, 'x-mailer');
  const xOrigIP    = get(h, 'x-originating-ip') || get(h, 'x-sender-ip');
  const spamStatus = get(h, 'x-spam-status');
  const spamScore  = get(h, 'x-spam-score');
  const priority   = get(h, 'x-priority') || get(h, 'importance');
  const authWarn   = get(h, 'x-authentication-warning');

  /* Auth */
  const authResultsRaw = get(h, 'authentication-results');
  const auth = parseAuthResults(authResultsRaw);

  if (auth.spf === 'none') {
    const spfH = get(h, 'received-spf');
    if (spfH) {
      const m = spfH.match(/^([a-z]+)/i);
      if (m) auth.spf = m[1].toLowerCase();
    }
  }

  const dkimSig = get(h, 'dkim-signature');
  if (auth.dkim === 'none' && dkimSig) auth.dkim = 'present';

  /* Routing */
  const receivedAll = getAll(h, 'received');
  const hops = receivedAll.map(parseReceived).reverse();

  /* Domain extraction */
  const fromAddr    = (from.match(/<([^>]+)>/) || from.match(/[\w.+%-]+@[\w.-]+/))?.[1] || from;
  const fromDomain  = fromAddr.includes('@') ? fromAddr.split('@')[1].toLowerCase() : '';
  const replyAddr   = (replyTo.match(/<([^>]+)>/) || [null, replyTo])[1] || replyTo;
  const replyDomain = replyAddr.includes('@') ? replyAddr.split('@')[1].toLowerCase() : '';
  const retAddr     = (returnPath.match(/<([^>]+)>/) || [null, returnPath])[1] || returnPath;
  const retDomain   = retAddr.includes('@') ? retAddr.split('@')[1].toLowerCase() : '';
  const dkimDomain  = dkimSig ? (dkimSig.match(/d=([^;\s]+)/i) || [])[1] || '' : '';

  /* ─── FINDINGS ─────────────────────────────────────────────────── */
  let riskScore = 0;
  const riskBreakdown = [];

  /* SPF */
  if (auth.spf === 'pass') {
    findings.push({ t: 'SPF check passed', d: 'Sender IP is authorised by the domain\'s SPF record.', l: 'green', i: '✓' });
  } else if (['fail', 'hardfail'].includes(auth.spf)) {
    findings.push({ t: 'SPF FAIL — sender IP not authorised', d: `The sending IP is not listed as authorised in the SPF record for ${fromDomain || 'this domain'}.`, l: 'red', i: '✕' });
    riskScore += 30; riskBreakdown.push({ label: 'SPF Fail', score: 30 });
  } else if (auth.spf === 'softfail') {
    findings.push({ t: 'SPF SoftFail — sender may not be authorised', d: 'The ~all mechanism was matched. Sender may not be authorised.', l: 'amber', i: '⚠' });
    riskScore += 15; riskBreakdown.push({ label: 'SPF SoftFail', score: 15 });
  } else {
    findings.push({ t: 'SPF result missing or none', d: 'No SPF check performed or no SPF record found.', l: 'amber', i: '⚠' });
    riskScore += 10; riskBreakdown.push({ label: 'SPF Missing', score: 10 });
  }

  /* DKIM */
  if (auth.dkim === 'pass') {
    findings.push({ t: 'DKIM signature verified', d: 'Email cryptographically verified — no tampering detected.', l: 'green', i: '✓' });
  } else if (auth.dkim === 'fail') {
    findings.push({ t: 'DKIM FAIL — signature invalid or tampered', d: 'DKIM signature did not verify. Message may have been modified in transit.', l: 'red', i: '✕' });
    riskScore += 35; riskBreakdown.push({ label: 'DKIM Fail', score: 35 });
  } else if (auth.dkim === 'present') {
    findings.push({ t: 'DKIM signature present but result not confirmed', d: 'A DKIM-Signature header exists but authentication-results do not confirm pass/fail.', l: 'amber', i: '⚠' });
    riskScore += 5;
  } else {
    findings.push({ t: 'DKIM not present or not verified', d: 'No DKIM signature found. Message authenticity cannot be cryptographically verified.', l: 'amber', i: '⚠' });
    riskScore += 15; riskBreakdown.push({ label: 'DKIM Missing', score: 15 });
  }

  /* DMARC */
  if (auth.dmarc === 'pass') {
    findings.push({ t: 'DMARC policy passed', d: 'From domain alignment passed DMARC policy enforcement.', l: 'green', i: '✓' });
  } else if (auth.dmarc === 'fail') {
    findings.push({ t: 'DMARC FAIL — alignment failure, possible spoofing', d: `The From header domain (${fromDomain}) did not align with SPF or DKIM authenticated domains.`, l: 'red', i: '✕' });
    riskScore += 35; riskBreakdown.push({ label: 'DMARC Fail', score: 35 });
  } else {
    findings.push({ t: 'DMARC result not found', d: 'DMARC was not evaluated or the domain lacks a DMARC policy.', l: 'amber', i: '⚠' });
    riskScore += 10; riskBreakdown.push({ label: 'DMARC Missing', score: 10 });
  }

  /* Reply-To mismatch */
  if (replyTo && replyDomain && fromDomain && replyDomain !== fromDomain) {
    findings.push({ t: 'Reply-To domain mismatch — phishing indicator', d: `From: ${fromDomain} → Reply-To: ${replyDomain}. Replies go to a different domain — classic phishing technique.`, l: 'red', i: '✕' });
    riskScore += 40; riskBreakdown.push({ label: 'Reply-To Mismatch', score: 40 });
  }

  /* Return-Path mismatch */
  if (returnPath && retDomain && fromDomain && retDomain !== fromDomain) {
    findings.push({ t: 'Return-Path domain differs from From', d: `From: ${fromDomain} → Return-Path: ${retDomain}. May indicate spoofing or third-party sending.`, l: 'amber', i: '⚠' });
    riskScore += 20; riskBreakdown.push({ label: 'Return-Path Mismatch', score: 20 });
  }

  /* DKIM domain alignment */
  if (dkimDomain && fromDomain && dkimDomain !== fromDomain) {
    findings.push({ t: `DKIM domain (${dkimDomain}) differs from From domain`, d: 'The signing domain is not the same as the From address domain.', l: 'amber', i: '⚠' });
    riskScore += 10;
  }

  /* Message-ID */
  if (!msgId) {
    findings.push({ t: 'Missing Message-ID header', d: 'Legitimate mail servers always add a Message-ID. Absence may indicate spoofed mail.', l: 'amber', i: '⚠' });
    riskScore += 10;
  }

  /* Date checks */
  if (!date) {
    findings.push({ t: 'Missing Date header', d: 'No Date header found. Required by RFC 5322.', l: 'amber', i: '⚠' });
    riskScore += 5;
  } else {
    const d = new Date(date);
    if (!isNaN(d)) {
      const diffDays = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24);
      if (diffDays < 0) {
        findings.push({ t: 'Date header is in the future', d: `Email claims to be sent ${Math.abs(Math.round(diffDays))} day(s) in the future. Possible timestamp manipulation.`, l: 'red', i: '✕' });
        riskScore += 15;
      }
    }
  }

  /* Hop analysis */
  if (hops.length === 0) {
    findings.push({ t: 'No Received headers found', d: 'Cannot trace routing. Headers may have been stripped — suspicious for external mail.', l: 'amber', i: '⚠' });
  } else {
    if (hops.length > 6) {
      findings.push({ t: `High hop count (${hops.length} hops)`, d: `Email passed through ${hops.length} servers. High counts may indicate anonymous relay infrastructure.`, l: 'amber', i: '⚠' });
      riskScore += 10;
    }
    hops.forEach(hop => {
      if (hop.from.toLowerCase().includes('unknown') && hop.ip && !isPrivateIP(hop.ip)) {
        findings.push({ t: `Unknown relay hostname: ${hop.ip}`, d: `A hop from an UNKNOWN hostname was detected in the routing chain.`, l: 'amber', i: '⚠' });
        riskScore += 8;
      }
    });
  }

  /* Spam headers */
  if (spamStatus && /\byes\b/i.test(spamStatus)) {
    findings.push({ t: 'Spam filter flagged this message', d: `X-Spam-Status: ${spamStatus}${spamScore ? ` (score: ${spamScore})` : ''}`, l: 'red', i: '✕' });
    riskScore += 20;
  }

  /* X-Mailer */
  if (xMailer) {
    const suspiciousMailers = ['phpmailer', 'python', 'curl', 'smtp2go', 'sendblaster', 'massmailer'];
    const isSusp = suspiciousMailers.some(s => xMailer.toLowerCase().includes(s));
    findings.push({ t: `X-Mailer: ${xMailer}`, d: isSusp ? 'This mailer is commonly used in bulk/phishing campaigns.' : 'Mail client identifier found.', l: isSusp ? 'amber' : 'blue', i: isSusp ? '⚠' : 'i' });
    if (isSusp) riskScore += 8;
  }

  /* Priority */
  if (priority && (priority === '1' || priority.toLowerCase() === 'high')) {
    findings.push({ t: 'High-priority flag set', d: 'Email marked as urgent/high priority. Phishing emails often use this to create urgency.', l: 'amber', i: '⚠' });
    riskScore += 5;
  }

  /* Originating IP */
  if (xOrigIP) {
    findings.push({ t: `Originating IP: ${xOrigIP}`, d: `${isPrivateIP(xOrigIP) ? 'Private/internal IP — normal for internal mail.' : 'Public IP found. Consider checking against threat intel feeds.'}`, l: 'blue', i: 'i' });
  }

  /* Auth warning */
  if (authWarn) {
    findings.push({ t: 'Authentication warning present', d: `X-Authentication-Warning: ${authWarn}`, l: 'amber', i: '⚠' });
    riskScore += 10;
  }

  /* All clear */
  if (findings.filter(f => f.l === 'red').length === 0 && riskScore === 0) {
    findings.push({ t: 'No critical issues detected', d: 'Authentication checks passed and no major anomalies found. Always apply human judgement.', l: 'green', i: '✓' });
  }

  riskScore = Math.min(100, riskScore);

  /* ─── RENDER ALL ─────────────────────────────────────────────── */
  renderSummary(riskScore, hops.length, findings, auth);
  renderOverview(h, from, to, subject, date, msgId, replyTo, returnPath, riskScore, riskBreakdown, auth);
  renderAuth(auth, authResultsRaw, fromDomain, replyDomain, retDomain, dkimDomain);
  renderRouting(hops, xOrigIP);
  renderFindings(findings);
  renderRaw(h);

  document.getElementById('results').classList.remove('hidden');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  switchTabByName('overview');
}

/* ─── Render: Summary ────────────────────────────────────────────── */
function renderSummary(riskScore, hopCount, findings, auth) {
  const authScore = ['spf', 'dkim', 'dmarc'].filter(k => auth[k] === 'pass').length;
  const riskLabel = riskScore >= 60 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW';
  const riskClass = riskScore >= 60 ? 'risk-high' : riskScore >= 30 ? 'risk-med' : 'risk-low';
  const barClass  = riskScore >= 60 ? 'risk-bar-high' : riskScore >= 30 ? 'risk-bar-med' : 'risk-bar-low';

  document.getElementById('s-risk-score').textContent = riskScore;
  document.getElementById('s-auth').textContent = `${authScore}/3`;
  document.getElementById('s-hops').textContent = hopCount;
  document.getElementById('s-findings').textContent = findings.length;

  const labelEl = document.getElementById('s-risk-label');
  labelEl.textContent = riskLabel;
  labelEl.className = `sum-risk-label ${riskClass}`;

  const fill = document.getElementById('riskBarFill');
  fill.style.width = riskScore + '%';
  fill.className = `risk-bar-fill ${barClass}`;

  document.getElementById('findings-badge').textContent = findings.filter(f => f.l === 'red').length;
}

/* ─── Render: Overview ───────────────────────────────────────────── */
function renderOverview(h, from, to, subject, date, msgId, replyTo, returnPath, riskScore, riskBreakdown, auth) {
  const kvData = [
    ['From', from], ['To', to], ['Subject', subject], ['Date', date],
    ['Message-ID', msgId], ['Reply-To', replyTo], ['Return-Path', returnPath]
  ];

  document.getElementById('envelope-list').innerHTML = kvData.map(([k, v]) =>
    `<div class="kv-row">
      <div class="kv-key">${k}</div>
      <div class="kv-val ${v ? '' : 'kv-empty'}">${v ? escapeHtml(v) : '—'}</div>
    </div>`
  ).join('');

  const barClass = riskScore >= 60 ? 'risk-bar-high' : riskScore >= 30 ? 'risk-bar-med' : 'risk-bar-low';
  const riskClass = riskScore >= 60 ? 'risk-high' : riskScore >= 30 ? 'risk-med' : 'risk-low';

  let bdHtml = `<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
    <span style="font-size:36px;font-weight:800;font-family:var(--font-mono)" class="${riskClass}">${riskScore}</span>
    <div>
      <div class="sum-lbl" style="margin-bottom:4px">Overall Risk Score</div>
      <div class="risk-bar-wrap" style="width:160px">
        <div class="risk-bar-fill ${barClass}" style="width:${riskScore}%"></div>
      </div>
    </div>
  </div>`;

  if (riskBreakdown.length > 0) {
    bdHtml += `<div class="risk-items">` + riskBreakdown.map(rb =>
      `<div class="risk-item">
        <div class="risk-item-label">${escapeHtml(rb.label)}</div>
        <div class="risk-item-bar-wrap">
          <div class="risk-item-bar ${rb.score >= 30 ? 'risk-bar-high' : rb.score >= 15 ? 'risk-bar-med' : 'risk-bar-low'}"
            style="width:${Math.min(100, (rb.score / 40) * 100)}%"></div>
        </div>
        <div class="risk-item-score">+${rb.score}</div>
      </div>`
    ).join('') + `</div>`;
  } else {
    bdHtml += `<div style="font-size:13px;color:var(--green)">✓ No risk factors detected</div>`;
  }

  document.getElementById('risk-breakdown').innerHTML = bdHtml;

  document.getElementById('auth-pills-overview').innerHTML =
    ['spf', 'dkim', 'dmarc'].map(k =>
      `${badge(auth[k])} <span style="font-size:11px;color:var(--text3);margin-right:10px">${k.toUpperCase()}</span>`
    ).join('');
}

/* ─── Render: Auth ───────────────────────────────────────────────── */
function renderAuth(auth, authResultsRaw, fromDomain, replyDomain, retDomain, dkimDomain) {
  const items = [
    { name: 'SPF',   key: 'spf',   detail: 'Sender Policy Framework' },
    { name: 'DKIM',  key: 'dkim',  detail: 'DomainKeys Identified Mail' },
    { name: 'DMARC', key: 'dmarc', detail: 'Domain-based Msg Auth' },
    { name: 'ARC',   key: 'arc',   detail: 'Authenticated Received Chain' }
  ];

  document.getElementById('auth-grid').innerHTML = items.map(item => `
    <div class="auth-item">
      <div class="auth-item-name">${item.name}</div>
      <div class="auth-item-result">${badge(auth[item.key])}</div>
      <div class="auth-item-detail">${item.detail}</div>
    </div>
  `).join('');

  const dkimAlign = dkimDomain && fromDomain ? dkimDomain === fromDomain : null;
  const retAlign  = retDomain  && fromDomain ? retDomain  === fromDomain : null;
  const rtAlign   = replyDomain && fromDomain ? replyDomain === fromDomain : null;

  document.getElementById('align-section').innerHTML = `
    <div class="align-grid">
      <div class="align-item">
        <div class="align-label">From domain</div>
        <div class="align-val">${escapeHtml(fromDomain) || '—'}</div>
      </div>
      <div class="align-item">
        <div class="align-label">DKIM signed domain</div>
        <div class="align-val">${escapeHtml(dkimDomain) || '—'}</div>
        ${dkimAlign !== null ? `<div class="align-match">${dkimAlign ? badge('pass') : badge('fail')} alignment</div>` : ''}
      </div>
      <div class="align-item">
        <div class="align-label">Return-Path domain</div>
        <div class="align-val">${escapeHtml(retDomain) || '—'}</div>
        ${retAlign !== null ? `<div class="align-match">${retAlign ? badge('pass') : badge('fail')} alignment</div>` : ''}
      </div>
      <div class="align-item">
        <div class="align-label">Reply-To domain</div>
        <div class="align-val">${escapeHtml(replyDomain) || '—'}</div>
        ${rtAlign !== null ? `<div class="align-match">${rtAlign ? badge('pass') : badge('fail')} alignment</div>` : ''}
      </div>
    </div>`;

  document.getElementById('raw-auth-block').textContent = authResultsRaw || 'Authentication-Results header not found.';
  document.getElementById('raw-auth-card').style.display = authResultsRaw ? '' : 'none';
}

/* ─── Render: Routing ────────────────────────────────────────────── */
function renderRouting(hops, xOrigIP) {
  const tbody = document.getElementById('hop-tbody');

  if (hops.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:24px">No Received headers found</td></tr>`;
  } else {
    tbody.innerHTML = hops.map((hop, i) => {
      const delay = (i > 0 && hop.date && hops[i - 1].date)
        ? Math.round((hop.date - hops[i - 1].date) / 1000) + 's'
        : '—';
      const isPriv = hop.ip && isPrivateIP(hop.ip);
      const typeLabel = !hop.ip
        ? '<span style="color:var(--text3)">—</span>'
        : isPriv
          ? `<span class="badge badge-info">Internal</span>`
          : `<span class="badge badge-pass">External</span>`;
      const delayColor = parseInt(delay) > 60 ? 'color:var(--amber)' : '';

      return `<tr>
        <td><div class="hop-num">${i + 1}</div></td>
        <td>${escapeHtml(hop.from) || '—'}</td>
        <td>${escapeHtml(hop.by) || '—'}</td>
        <td>${hop.ip ? `<span style="font-family:var(--font-mono)">${escapeHtml(hop.ip)}</span>` : '—'}</td>
        <td style="font-size:11px">${escapeHtml(hop.dateStr) || '—'}</td>
        <td style="${delayColor}">${delay}</td>
        <td>${typeLabel}</td>
      </tr>`;
    }).join('');
  }

  /* Originating IP */
  const firstExtHop = hops.find(h => h.ip && !isPrivateIP(h.ip));
  const originSection = document.getElementById('origin-ip-section');
  const ip = xOrigIP || (firstExtHop ? firstExtHop.ip : '');

  if (ip) {
    originSection.innerHTML = `
      <div class="origin-ip-grid">
        <div class="align-item">
          <div class="align-label">Detected originating IP</div>
          <div class="align-val" style="font-size:15px;margin-top:4px">${escapeHtml(ip)}</div>
        </div>
        <div class="align-item">
          <div class="align-label">IP type</div>
          <div class="align-val" style="margin-top:4px">${isPrivateIP(ip) ? '🏢 Private / Internal' : '🌐 Public / External'}</div>
        </div>
        <div class="align-item">
          <div class="align-label">Threat intel lookup</div>
          <div style="margin-top:6px;display:flex;flex-direction:column;gap:6px">
            <a href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}" target="_blank"
              style="color:var(--accent);text-decoration:none;font-size:12px;font-family:var(--font-mono)">
              ↗ VirusTotal
            </a>
            <a href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank"
              style="color:var(--accent);text-decoration:none;font-size:12px;font-family:var(--font-mono)">
              ↗ AbuseIPDB
            </a>
            <a href="https://threatintelligenceplatform.com/indicator/${encodeURIComponent(ip)}" target="_blank"
              style="color:var(--accent);text-decoration:none;font-size:12px;font-family:var(--font-mono)">
              ↗ TIP Lookup
            </a>
          </div>
        </div>
      </div>`;
  } else {
    originSection.innerHTML = `<div style="color:var(--text3);font-size:13px">No originating IP detected in headers.</div>`;
  }
}

/* ─── Render: Findings ───────────────────────────────────────────── */
function renderFindings(findings) {
  document.getElementById('findings-list').innerHTML = findings.map(f => `
    <div class="finding finding-${f.l}">
      <div class="finding-icon">${f.i}</div>
      <div class="finding-body">
        <div class="finding-title">${escapeHtml(f.t)}</div>
        ${f.d ? `<div class="finding-desc">${escapeHtml(f.d)}</div>` : ''}
      </div>
    </div>
  `).join('');
}

/* ─── Render: Raw ────────────────────────────────────────────────── */
function renderRaw(h) {
  const lines = Object.entries(h).map(([k, v]) => {
    const vals = Array.isArray(v) ? v : [v];
    return vals.map(val => `${k}: ${val}`).join('\n');
  }).join('\n');
  document.getElementById('raw-parsed').textContent = lines;
}

/* ─── Tab Switcher ───────────────────────────────────────────────── */
function switchTab(btn, name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.remove('active');
    p.classList.add('hidden');
  });
  btn.classList.add('active');
  const pane = document.getElementById('tab-' + name);
  pane.classList.remove('hidden');
  pane.classList.add('active');
}

function switchTabByName(name) {
  const tabs = ['overview', 'auth', 'routing', 'findings', 'raw'];
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', tabs[i] === name);
  });
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.remove('active');
    p.classList.add('hidden');
  });
  const pane = document.getElementById('tab-' + name);
  if (pane) {
    pane.classList.remove('hidden');
    pane.classList.add('active');
  }
}

/* ─── Clear ──────────────────────────────────────────────────────── */
function clearAll() {
  document.getElementById('emlInput').value = '';
  document.getElementById('results').classList.add('hidden');
  resetInputHint();
  const fileInput = document.getElementById('emlFileInput');
  if (fileInput) fileInput.value = '';
}
