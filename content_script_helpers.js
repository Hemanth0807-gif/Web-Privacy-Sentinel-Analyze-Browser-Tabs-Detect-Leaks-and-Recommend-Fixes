// content_script_helpers.js
(function () {
  if (window.__WPS) return;

  function detectMixedContent() {
    const insecureEls = [];
    try {
      document.querySelectorAll('img[src], script[src], link[href], iframe[src], video[src], audio[src]').forEach(el => {
        const url = (el.src || el.href || el.getAttribute('src') || el.getAttribute('href') || '').toLowerCase();
        if (url.startsWith('http://')) insecureEls.push(url);
      });
    } catch (e) {}
    return insecureEls.length > 0 ? { mixedContent: true, examples: insecureEls.slice(0,5) } : { mixedContent: false };
  }

  function detectTrackers() {
    const trackersFound = [];
    const known = [
      'google-analytics.com','analytics.google.com','connect.facebook.net','ads.twitter.com',
      'bat.bing.com','cdn.segment.com','googletagmanager.com','facebook.net',
      'doubleclick.net','pubmatic.com','rubiconproject.com','adnxs.com','criteo.com',
      'taboola.com','outbrain.com','amazon-adsystem.com','scorecardresearch.com'
    ];
    try {
      document.querySelectorAll('script[src], img[src], iframe[src]').forEach(el => {
        const src = (el.src || el.getAttribute('src') || '').toLowerCase();
        known.forEach(host => { 
          if (new RegExp(host.replace('.', '\\.'), 'i').test(src) && !trackersFound.includes(host)) trackersFound.push(host); 
        });
      });
      if (window.ga && typeof window.ga === 'function' && !trackersFound.includes('google-analytics.com')) trackersFound.push('google-analytics.com');
      if (window.dataLayer && Array.isArray(window.dataLayer) && !trackersFound.includes('googletagmanager.com')) trackersFound.push('googletagmanager.com');
    } catch (e) {}
    return trackersFound;
  }

  function detectFingerprinting() {
    let fingerprinting = false;
    let canvasAccessDetected = false;
    try {
      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function () {
        canvasAccessDetected = true;
        return originalToDataURL.apply(this, arguments);
      };
      setTimeout(() => { HTMLCanvasElement.prototype.toDataURL = originalToDataURL; }, 50);
    } catch (e) {}
    const libs = ['fingerprintjs', 'fingerprint2', 'fingerprintjs2', 'clientjs'];
    let knownFP = false;
    try {
      const html = document.documentElement.innerHTML.toLowerCase();
      libs.forEach(lib => { if (html.includes(lib)) knownFP = true; });
    } catch (e) {}
    fingerprinting = canvasAccessDetected || knownFP;
    return fingerprinting;
  }

  function detectInlineEventHandlersAndJsLinks() {
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
    return { inlineHandlers: inlineHandlers.slice(0,5), jsLinks: jsLinks.slice(0,5) };
  }

  function getThirdPartyCookies() {
    const all = document.cookie.split(';').map(c => c.trim());
    const own = location.hostname;
    return all
      .filter(c => c && !c.split('=')[0].includes(own))
      .map(c => {
        const [name, ...rest] = c.split('=');
        return { name: name.trim(), value: rest.join('=').trim() };
      })
      .slice(0, 5);
  }

  window.__WPS = {
    runChecks: function () {
      const out = {
        exposures: [],
        permissions: {},
        trackers: [],
        fingerprintingDetected: false,
        mixedContent: false,
        inlineHandlers: [],
        jsLinks: [],
        cookies: []
      };
      try {
        const mixed = detectMixedContent();
        if (mixed.mixedContent) {
          out.mixedContent = true;
          out.exposures.push('Mixed insecure resources');
        }
        const trackers = detectTrackers();
        if (trackers.length) {
          out.trackers = trackers;
          out.exposures.push(...trackers.map(t => `Tracker: ${t}`));
        }
        const fp = detectFingerprinting();
        if (fp) {
          out.fingerprintingDetected = true;
          out.exposures.push('Possible fingerprinting');
        }
        const eventCheck = detectInlineEventHandlersAndJsLinks();
        if (eventCheck.inlineHandlers.length) {
          out.inlineHandlers = eventCheck.inlineHandlers;
          out.exposures.push('Inline event handlers detected (possible XSS vectors)');
        }
        if (eventCheck.jsLinks.length) {
          out.jsLinks = eventCheck.jsLinks;
          out.exposures.push('javascript: links detected (possible XSS vectors)');
        }
        const cookies = getThirdPartyCookies();
        if (cookies.length) {
          out.cookies = cookies;
          out.exposures.push(`Third-party cookies detected (${cookies.length})`);
        }
      } catch (err) {
        out.exposures.push('page-check-error');
      }
      return out;
    }
  };
})();