// syslog-anonymizer.js
/*
  Syslog Anonymizer – Core anonymization logic
  Copyright (c) 2025 Brands ICT

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, … (the rest is in the LICENSE file)

  Full license: https://github.com/yourusername/syslog-anonymizer/blob/main/LICENSE
*/

(function(){
  // Deterministic maps for consistent replacements within a session
  const userMap = new Map();
  const hostMap = new Map();
  let userCounter = 1;
  let hostCounter = 1;

  // Regexes tuned for syslog-like text (balanced recall/precision)
  const rx = {
    ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b/g,
    ipv6: /\b([0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}\b/gi, // basic IPv6 (no full RFC coverage but good recall)
    mac: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    // Hostnames (RFC-lite): allow dots and hyphens; avoid matching URLs by excluding "://"
    hostname: /\b(?!https?:\/\/)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi,
    // URLs (captures protocol and domain; leaves path anonymized)
    url: /\bhttps?:\/\/[^\s]+/gi,
    // Common username capture following "for <user>" or "user <name>" or "login for <name>"
    userFor: /\b(?:for|user|login for)\s+([a-zA-Z0-9._-]{1,64})\b/g,
    // Timestamps (various formats commonly seen in syslog)
    ts1: /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/g,
    ts2: /\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b/g,
	uuid: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi

  };

  // Replacement helpers
  function replaceDeterministic(map, key, prefix) {
    if (!map.has(key)) map.set(key, prefix + String(map === userMap ? userCounter++ : hostCounter++).padStart(3, '0'));
    return map.get(key);
  }

  function anonymize(text, opts) {
    let out = text;

    if (opts.ts) {
      out = out.replace(rx.ts1, 'MMM DD HH:MM:SS');
      out = out.replace(rx.ts2, 'YYYY-MM-DD HH:MM:SSZ');
    }
    if (opts.ip4) out = out.replace(rx.ipv4, 'x.x.x.x');
    if (opts.ip6) out = out.replace(rx.ipv6, 'xxxx:xxxx::xxxx');
    if (opts.mac) out = out.replace(rx.mac, 'aa:aa:aa:aa:aa:aa');
    if (opts.email) out = out.replace(rx.email, 'anon@domain');
	if (opts.uuid) out = out.replace(rx.uuid, 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');


    if (opts.url) {
      out = out.replace(rx.url, function(m){
        try {
          const u = new URL(m);
          return (u.protocol + '//' + 'redacted' + (u.pathname ? '/...' : ''));
        } catch(e) { return 'https://redacted'; }
      });
    }

    if (opts.host) {
      out = out.replace(rx.hostname, function(m){
        // Avoid replacing already-redacted values or obvious TLD-only words
        if (m === 'redacted' || m === 'anon.lan') return m;
        return replaceDeterministic(hostMap, m.toLowerCase(), 'host_');
      });
    }

    if (opts.user) {
      out = out.replace(rx.userFor, function(_, user){
        const anon = replaceDeterministic(userMap, user, 'user_');
        return _.replace(user, anon);
      });
    }

    // Final pass: normalize any host_* to anon.lan if you prefer a generic value
    // Comment out to keep host_### format
    out = out.replace(/\bhost_\d{3}\b/g, 'anon.lan');

    return out;
  }

  // Wire up UI
  const $ = id => document.getElementById(id);
  $('runBtn').addEventListener('click', () => {
    const opts = {
      ip4: $('ip4').checked,
      ip6: $('ip6').checked,
      host: $('host').checked,
      mac: $('mac').checked,
      email: $('email').checked,
      user: $('user').checked,
      url: $('url').checked,
      ts: $('ts').checked
    };
    $('output').value = anonymize($('input').value, opts);
  });
  $('copyBtn').addEventListener('click', async () => {
    const txt = $('output').value;
    if (!txt) return;
    try { await navigator.clipboard.writeText(txt); } catch(e) { /* noop */ }
  });
  $('clearBtn').addEventListener('click', () => {
    $('input').value = '';
    $('output').value = '';
    userMap.clear(); hostMap.clear(); userCounter = 1; hostCounter = 1;
  });
})();