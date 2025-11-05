// background.js (MV3 service worker) — includes XSS heuristics + exposed data
const DEFAULT_EXTENSION_NOTE = 'Web Privacy Sentinel Helper';
const TRACKER_HOSTS = [
  'google-analytics.com','analytics.google.com','connect.facebook.net','ads.twitter.com',
  'bat.bing.com','cdn.segment.com','googletagmanager.com','facebook.net',
  'doubleclick.net','pubmatic.com','rubiconproject.com','adnxs.com','criteo.com',
  'taboola.com','outbrain.com','amazon-adsystem.com','scorecardresearch.com'
];

chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
  if (request.action === "scanTabs") {
    console.log("[WPS DEBUG] scanTabs requested");
    scanAllTabs()
      .then(tabs => {
        console.log("[WPS DEBUG] scanAllTabs result:", tabs.map(t => ({ url: t.url, riskScore: t.riskScore })));
        sendResponse({ tabs });
      })
      .catch(err => {
        console.error("[WPS DEBUG] scanAllTabs error:", err);
        sendResponse({ error: String(err) });
      });
    return true;
  }
});

async function scanAllTabs() {
  const tabs = await queryAllTabs();
  console.log("[WPS DEBUG] All tabs fetched:", tabs.map(t => t.url));
  const filtered = (tabs || []).filter(t => {
    if (!t.url) return false;
    const isExcluded =
      t.url.startsWith('chrome://') ||
      t.url.startsWith('about:') ||
      t.url.startsWith('file://') ||
      t.url.startsWith('http://localhost') ||
      t.url.startsWith('https://localhost') ||
      t.url.startsWith('http://127.0.0.1') ||
      t.url.startsWith('https://127.0.0.1');
    if (isExcluded) console.log("[WPS DEBUG] Excluding tab URL:", t.url);
    return !isExcluded;
  });

  const tabDataPromises = filtered.map(async (tab) => {
    const url = tab.url;
    console.log("[WPS DEBUG] Scanning tab URL:", url);
    const [
      httpsResult,
      webrtcResult,
      inPageQuick,
      inPageAsync
    ] = await Promise.all([
      checkHTTPS(url),
      checkWebRTCRisk(url),
      runInPageQuickChecks(tab.id),
      runInPageAsyncChecks(tab.id)
    ]);
    const xssResult = await checkXSSRisk(url);

    // ── EXPOSED DATA COLLECTION ───────────────────────────────────────
    const exposedData = {
      reflectedToken: xssResult.reflected ? xssResult.token : null,
      inlineHandlers: (inPageQuick.inlineHandlers || []).slice(0, 5),
      jsLinks: (inPageQuick.jsLinks || []).slice(0, 5),
      thirdPartyCookies: (inPageQuick.cookies || []).slice(0, 5),
      grantedPermissions: Object.entries(inPageAsync.permissions || {})
        .filter(([,v]) => v === 'granted')
        .map(([k]) => k),
      clipboardWriteGranted: (inPageAsync.permissions || {})['clipboard-write'] === 'granted'
    };

    const exposures = [
      ...httpsResult.exposures,
      ...(inPageQuick.exposures || []),
      ...(inPageAsync.exposures || []),
      ...(xssResult.exposures || [])
    ];
    const trackers = [...new Set([...(inPageQuick.trackers || []), ...(inPageAsync.trackers || [])])];
    const fingerprintingDetected = !!(inPageQuick.fingerprintingDetected || inPageAsync.fingerprintingDetected);
    const mixedContent = !!(inPageQuick.mixedContent || inPageAsync.mixedContent);
    const permissions = Object.assign({}, inPageAsync.permissions || {}, inPageQuick.permissions || {});
    if (webrtcResult.enabled && webrtcResult.riskySite) exposures.push('Potential WebRTC IP Leak');

    const pageChecks = { trackers, fingerprintingDetected, mixedContent, permissions, xss: xssResult };
    const riskScore = computeRiskScore({ url, exposures, webrtcRisk: webrtcResult, pageChecks });

    return {
      title: tab.title || 'Untitled',
      url,
      hostname: (new URL(url)).hostname,
      exposures: dedupeStrings(exposures),
      webrtcRisk: webrtcResult,
      pageChecks,
      riskScore,
      exposedData
    };
  });
  return Promise.all(tabDataPromises);
}

function queryAllTabs() {
  return new Promise((resolve) => chrome.tabs.query({}, tabs => resolve(tabs || [])));
}

function dedupeStrings(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
}

async function checkHTTPS(url) {
  const exposures = [];
  try {
    const u = new URL(url);
    if (
      u.protocol !== 'https:' &&
      u.protocol !== 'file:' &&
      !u.hostname.startsWith('localhost') &&
      u.hostname !== '127.0.0.1'
    ) {
      exposures.push('Unencrypted Connection (HTTP)');
    }
  } catch (e) {
    console.warn("[WPS DEBUG] HTTPS check failed URL parse:", url, e);
  }
  return { exposures };
}

async function checkWebRTCRisk(url) {
  return new Promise((resolve) => {
    try {
      if (!chrome.privacy || !chrome.privacy.network || !chrome.privacy.network.webRTCIPHandlingPolicy) {
        resolve({ enabled: true, riskySite: false, note: 'Privacy API not available' });
        return;
      }
      chrome.privacy.network.webRTCIPHandlingPolicy.get({}, (details) => {
        if (chrome.runtime.lastError || !details) {
          resolve({ enabled: true, riskySite: false, note: 'Could not read WebRTC policy' });
          return;
        }
        const isWebRTCRestricted = details.value === 'disable_non_proxied_udp' || details.value === 'default_public_interface_only';
        const heuristics = ['meet', 'call', 'conference', 'webinar', 'video', 'join'];
        const u = (url || '').toLowerCase();
        const hostname = (() => { try { return new URL(u).hostname; } catch(e) { return u; } })();
        const riskyDomains = ['zoom.us', 'meet.google.com', 'webex.com', 'skype.com', 'discord.com'];
        const isRiskyDomain = riskyDomains.some(d => hostname.includes(d));
        const heuristicUse = heuristics.some(h => u.includes(h));
        resolve({
          enabled: !isWebRTCRestricted,
          riskySite: isRiskyDomain || heuristicUse,
          note: isWebRTCRestricted ? 'WebRTC restricted by browser settings' : (isRiskyDomain ? 'Site known to use WebRTC' : (heuristicUse ? 'URL suggests real-time/meeting usage' : 'WebRTC allowed'))
        });
      });
    } catch (e) {
      resolve({ enabled: true, riskySite: false, note: 'Error checking WebRTC' });
    }
  });
}

async function runInPageQuickChecks(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        try {
          const currentUrl = window.location.href;
          if (
            currentUrl.startsWith('file://') ||
            currentUrl.startsWith('http://localhost') ||
            currentUrl.startsWith('https://localhost') ||
            currentUrl.startsWith('http://127.0.0.1') ||
            currentUrl.startsWith('https://127.0.0.1')
          ) {
            return { exposures: [], trackers: [], fingerprintingDetected: false, mixedContent: false, permissions: {}, cookies: [], inlineHandlers: [], jsLinks: [] };
          }

          // Mixed content
          const insecureEls = [];
          document.querySelectorAll('img[src], script[src], link[href], iframe[src], video[src], audio[src]').forEach(el => {
            const url = (el.src || el.href || el.getAttribute('src') || el.getAttribute('href') || '').toLowerCase();
            if (url.startsWith('http://')) insecureEls.push(url);
          });

          // Trackers
          const trackersFound = [];
          const known = [
            'google-analytics.com','analytics.google.com','connect.facebook.net','ads.twitter.com',
            'bat.bing.com','cdn.segment.com','googletagmanager.com','facebook.net',
            'doubleclick.net','pubmatic.com','rubiconproject.com','adnxs.com','criteo.com',
            'taboola.com','outbrain.com','amazon-adsystem.com','scorecardresearch.com'
          ];
          document.querySelectorAll('script[src], img[src], iframe[src]').forEach(el => {
            const src = (el.src || el.getAttribute('src') || '').toLowerCase();
            known.forEach(host => { 
              if (new RegExp(host.replace('.', '\\.'), 'i').test(src) && !trackersFound.includes(host)) trackersFound.push(host); 
            });
          });
          if (window.ga && typeof window.ga === 'function' && !trackersFound.includes('google-analytics.com')) trackersFound.push('google-analytics.com');
          if (window.dataLayer && Array.isArray(window.dataLayer) && !trackersFound.includes('googletagmanager.com')) trackersFound.push('googletagmanager.com');

          // Fingerprinting
          let fingerprinting = false;
          try {
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function () {
              fingerprinting = true;
              return originalToDataURL.apply(this, arguments);
            };
            setTimeout(() => { HTMLCanvasElement.prototype.toDataURL = originalToDataURL; }, 50);
          } catch (e) { }

          // Inline handlers & javascript: links
          const inlineHandlers = [];
          const jsLinks = [];
          try {
            const all = document.querySelectorAll('*');
            all.forEach(el => {
              Array.from(el.attributes || []).forEach(attr => {
                const name = (attr.name || '').toLowerCase();
                const val = (attr.value || '').toLowerCase();
                if (name.startsWith('on')) {
                  inlineHandlers.push({ name, sample: (el.outerHTML || '').slice(0, 200) });
                }
                if ((name === 'href' || name === 'src') && val.includes('javascript:')) {
                  jsLinks.push({ attr: name, sample: (el.outerHTML || '').slice(0, 200) });
                }
              });
            });
          } catch (e) {}

          // Third-party cookies
          const allCookies = document.cookie.split(';').map(c => c.trim());
          const ownHost = location.hostname;
          const thirdPartyCookies = allCookies
            .filter(c => c && !c.split('=')[0].includes(ownHost))
            .map(c => {
              const [name, ...rest] = c.split('=');
              return { name: name.trim(), value: rest.join('=').trim() };
            });

          const out = {
            exposures: [],
            permissions: {},
            trackers: trackersFound,
            fingerprintingDetected: !!fingerprinting,
            mixedContent: insecureEls.length > 0,
            inlineHandlers: inlineHandlers.slice(0, 5),
            jsLinks: jsLinks.slice(0, 5),
            cookies: thirdPartyCookies.slice(0, 5)
          };

          if (out.mixedContent) out.exposures.push('Mixed insecure resources');
          if (trackersFound.length) out.exposures.push(...trackersFound.map(t => `Tracker: ${t}`));
          if (fingerprinting) out.exposures.push('Possible fingerprinting');
          if (inlineHandlers.length) out.exposures.push('Inline event handlers detected (possible XSS vectors)');
          if (jsLinks.length) out.exposures.push('javascript: links detected (possible XSS vectors)');
          if (thirdPartyCookies.length) out.exposures.push(`Third-party cookies detected (${thirdPartyCookies.length})`);

          return out;
        } catch (err) {
          return { exposures: ['page-check-error'], trackers: [], fingerprintingDetected: false, mixedContent: false, permissions: {}, cookies: [], inlineHandlers: [], jsLinks: [] };
        }
      }
    });
    return results[0].result || {};
  } catch (e) {
    console.error("[WPS DEBUG] runInPageQuickChecks error:", e);
    return { exposures: [], trackers: [], fingerprintingDetected: false, mixedContent: false, permissions: {}, cookies: [], inlineHandlers: [], jsLinks: [], error: String(e) };
  }
}

async function runInPageAsyncChecks(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: async () => {
        try {
          const currentUrl = window.location.href;
          if (
            currentUrl.startsWith('file://') ||
            currentUrl.startsWith('http://localhost') ||
            currentUrl.startsWith('https://localhost') ||
            currentUrl.startsWith('http://127.0.0.1') ||
            currentUrl.startsWith('https://127.0.0.1')
          ) {
            return { exposures: [], trackers: [], fingerprintingDetected: false, mixedContent: false, permissions: {} };
          }
          const permissions = {};
          const permsToCheck = ['geolocation', 'microphone', 'camera', 'clipboard-read', 'clipboard-write', 'notifications'];
          for (const p of permsToCheck) {
            try {
              const state = await navigator.permissions.query({ name: p });
              permissions[p] = state.state;
            } catch (e) {
              permissions[p] = 'error';
            }
          }
          const exposures = Object.entries(permissions)
            .filter(([, v]) => v === 'granted')
            .map(([k]) => `Granted: ${k}`);
          return { exposures, permissions, trackers: [], fingerprintingDetected: false, mixedContent: false };
        } catch (err) {
          return { exposures: ['page-async-check-error'], permissions: {}, trackers: [], fingerprintingDetected: false, mixedContent: false };
        }
      }
    });
    return results[0].result || {};
  } catch (e) {
    console.error("[WPS DEBUG] runInPageAsyncChecks error:", e);
    return { exposures: [], trackers: [], fingerprintingDetected: false, mixedContent: false, permissions: {}, error: String(e) };
  }
}

let __wps_token = null;
async function checkXSSRisk(url) {
  const out = {
    reflected: false,
    token: null,
    tokenOccurrences: 0,
    csp: null,
    exposures: []
  };
  try {
    const u = new URL(url);
    const token = `__wps_xss_test_${Math.random().toString(36).slice(2,10)}`;
    __wps_token = token;
    u.searchParams.set('__wps_xss_test', token);
    const testUrl = u.toString();
    console.log('[WPS DEBUG] checkXSSRisk fetching:', testUrl);

    let respText = null;
    let cspHeader = null;
    try {
      const resp = await fetch(testUrl, { method: 'GET', credentials: 'include', redirect: 'follow' });
      cspHeader = resp.headers ? resp.headers.get('content-security-policy') : null;
      respText = await resp.text();
    } catch (fe) {
      console.warn('[WPS DEBUG] checkXSSRisk fetch failed:', fe);
      out.exposures.push('XSS check: fetch failed or blocked');
      if (cspHeader) out.csp = cspHeader;
      return out;
    }

    out.csp = cspHeader || null;
    if (respText && respText.includes(token)) {
      out.reflected = true;
      out.token = token;
      let count = 0;
      let idx = respText.indexOf(token);
      while (idx !== -1) {
        count++;
        idx = respText.indexOf(token, idx + token.length);
      }
      out.tokenOccurrences = count;
      out.exposures.push(`Reflected token detected (${count} occurrence${count>1?'s':''}) — possible reflected XSS`);
    }

    if (!out.csp) {
      out.exposures.push('No Content-Security-Policy header present (reduces XSS mitigation)');
    } else {
      if (out.csp.includes('unsafe-inline') || out.csp.includes('data:') || out.csp.includes('*')) {
        out.exposures.push('Content-Security-Policy present but may allow inline scripts or broad sources (weaker CSP)');
      }
      if (out.csp.includes('unsafe-eval')) {
        out.exposures.push('Content-Security-Policy allows unsafe-eval (increases XSS risk)');
      }
    }
  } catch (e) {
    console.error('[WPS DEBUG] checkXSSRisk error:', e);
    out.exposures.push('XSS check error');
  }
  return out;
}

function computeRiskScore({ url, exposures, webrtcRisk, pageChecks }) {
  let score = 0;
  try {
    const uniqueExposures = new Set(exposures || []);
    score += uniqueExposures.size * 8;
    if (pageChecks && pageChecks.trackers && pageChecks.trackers.length > 0) {
      score += (pageChecks.trackers.length * 6);
    }
    if (pageChecks && pageChecks.fingerprintingDetected) score += 15;
    if (webrtcRisk && webrtcRisk.enabled && webrtcRisk.riskySite) score += 12;
    if (exposures && exposures.some(e => e.toLowerCase().includes('unencrypted') || e.toLowerCase().includes('http'))) score += 20;

    if (pageChecks && pageChecks.permissions) {
      const grantedCount = Object.values(pageChecks.permissions).filter(v => v === 'granted').length;
      score += grantedCount * 5;
    }
    if (pageChecks && pageChecks.cookies && pageChecks.cookies.length > 0) {
      score += pageChecks.cookies.length * 3;
    }

    const x = (pageChecks && pageChecks.xss) || {};
    if (x.reflected) {
      score += 30;
    } else {
      if (pageChecks && pageChecks.inlineHandlers && pageChecks.inlineHandlers.length) {
        score += 10;
      }
      if (x && x.csp && (x.csp.includes('unsafe-inline') || x.csp.includes('*') || x.csp.includes('data:'))) {
        score += 8;
      }
    }
    if (score > 100) score = 100;
  } catch (e) {
    score = 50;
  }
  return Math.round(score);
}