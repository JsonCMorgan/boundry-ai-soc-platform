/* Boundry.AI — platform-wide jargon hover cards.
   Wraps glossary terms (acronyms + phrases) in study pages, SIEM, Control Room, …
   Source: window.__BOUNDRY_JARGON or GET /api/acronyms.

   Safety:
   - longest-match first, case-insensitive, word-ish boundaries
   - skip script/style/input/textarea/code/pre/a/svg and data-no-gloss
   - text-node walker only (does not innerHTML ticking widgets)
   - safe to re-run; MutationObserver wraps AJAX-injected SIEM rows
   - 2-letter keys only if they are glossary abbrs (allowlist), never "log"/"all"/"in"
*/
(function () {
  "use strict";

  if (window.__boundryJargonBooted) return;
  window.__boundryJargonBooted = true;

  var SKIP_TAGS = {
    SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEXTAREA: 1, INPUT: 1, SELECT: 1,
    OPTION: 1, CODE: 1, PRE: 1, SVG: 1, CANVAS: 1, MATH: 1, IFRAME: 1,
    KBD: 1, SAMP: 1, A: 1
  };

  var pop = null;
  var popTimer = null;
  var activeEl = null;
  var coarse = false;
  // Pointer travel from underlined term → card. Cancelled on popover enter.
  var HIDE_DELAY_MS = 320;
  try {
    coarse = window.matchMedia("(hover: none), (pointer: coarse)").matches;
  } catch (e) {}

  function injectStyle() {
    if (document.getElementById("gloss-style")) return;
    var s = document.createElement("style");
    s.id = "gloss-style";
    s.textContent =
      "span.gloss{border-bottom:1px dotted #bb77ff;cursor:help;color:inherit;text-decoration:none;}" +
      "span.gloss:focus{outline:1px dashed #9944ee;outline-offset:2px;}" +
      "#jargon-pop{position:absolute;z-index:99999;max-width:280px;overflow:visible;" +
      "background:#131d28;border:1px solid #1e3045;border-radius:8px;padding:0;" +
      "box-shadow:0 12px 32px #000c;color:#cdd6e0;font-family:inherit;font-size:0.78em;line-height:1.45;" +
      "display:none;pointer-events:auto;}" +
      "#jargon-pop .jp-body{padding:10px 12px;max-height:40vh;overflow:auto;}" +
      "#jargon-pop.jp-below::before{content:'';position:absolute;left:0;right:0;top:-12px;height:16px;}" +
      "#jargon-pop.jp-above::after{content:'';position:absolute;left:0;right:0;bottom:-12px;height:16px;}" +
      "#jargon-pop .jp-term{font-weight:800;color:#bb77ff;font-family:Consolas,monospace;letter-spacing:0.03em;}" +
      "#jargon-pop .jp-exp{color:#9ab;font-size:0.92em;margin:2px 0 6px;}" +
      "#jargon-pop .jp-def{color:#cdd6e0;margin-bottom:8px;}" +
      "#jargon-pop .jp-link{color:#00d4ff;text-decoration:none;font-weight:700;font-size:0.92em;}" +
      "#jargon-pop .jp-link:hover{text-decoration:underline;}";
    document.head.appendChild(s);
  }

  function relatedIsGlossUi(node) {
    if (!node) return false;
    if (node.nodeType !== 1) node = node.parentElement;
    if (!node) return false;
    if (pop && (node === pop || pop.contains(node))) return true;
    if (activeEl && (node === activeEl || activeEl.contains(node))) return true;
    if (node.classList && node.classList.contains("gloss")) return true;
    return false;
  }

  function glossaryHref(info) {
    var slug = String((info && (info.id || info.term)) || "").replace(/ /g, "-");
    return "/glossary#gloss-" + slug;
  }

  function ensurePop() {
    if (pop) return pop;
    pop = document.createElement("div");
    pop.id = "jargon-pop";
    pop.setAttribute("role", "tooltip");
    pop.addEventListener("mouseenter", function () { clearTimeout(popTimer); });
    pop.addEventListener("mouseleave", function (e) {
      if (relatedIsGlossUi(e.relatedTarget)) return;
      scheduleHide(HIDE_DELAY_MS);
    });
    pop.addEventListener("focusin", function () { clearTimeout(popTimer); });
    pop.addEventListener("focusout", function (e) {
      if (relatedIsGlossUi(e.relatedTarget)) return;
      scheduleHide(HIDE_DELAY_MS);
    });
    document.body.appendChild(pop);
    return pop;
  }

  function hidePop() {
    clearTimeout(popTimer);
    if (pop) pop.style.display = "none";
    activeEl = null;
  }

  function scheduleHide(ms) {
    clearTimeout(popTimer);
    popTimer = setTimeout(hidePop, ms == null ? HIDE_DELAY_MS : ms);
  }

  function positionPop(anchor) {
    var p = ensurePop();
    p.style.display = "block";
    var r = anchor.getBoundingClientRect();
    var w = p.offsetWidth || 280;
    var h = p.offsetHeight || 80;
    // Overlap the term so mouseleave cannot fall through a gap.
    var overlap = 4;
    var left = r.left + window.scrollX;
    var placeAbove = r.bottom + overlap + (p.offsetHeight || h) > window.innerHeight && r.top > h + 8;
    p.classList.remove("jp-below", "jp-above");
    var top;
    if (placeAbove) {
      top = r.top + window.scrollY - (p.offsetHeight || h) + overlap;
      p.classList.add("jp-above");
    } else {
      top = r.bottom + window.scrollY - overlap;
      p.classList.add("jp-below");
    }
    if (left + w > window.scrollX + window.innerWidth - 8) {
      left = window.scrollX + window.innerWidth - w - 8;
    }
    if (left < window.scrollX + 8) left = window.scrollX + 8;
    p.style.left = Math.round(left) + "px";
    p.style.top = Math.round(top) + "px";
  }

  function showPop(el) {
    clearTimeout(popTimer);
    var info = el._gloss;
    if (!info) return;
    var p = ensurePop();
    var exp = info.expansion && info.expansion !== info.term ? info.expansion : "";
    var href = glossaryHref(info);
    p.innerHTML =
      '<div class="jp-body">' +
      '<div class="jp-term"></div>' +
      (exp ? '<div class="jp-exp"></div>' : "") +
      '<div class="jp-def"></div>' +
      '<a class="jp-link" href="' + href + '" target="_blank" rel="noopener noreferrer">Open in glossary →</a>' +
      "</div>";
    p.querySelector(".jp-term").textContent = info.term;
    if (exp) p.querySelector(".jp-exp").textContent = exp;
    p.querySelector(".jp-def").textContent = info.layman || "";
    var link = p.querySelector(".jp-link");
    link.addEventListener("click", function (e) { e.stopPropagation(); });
    link.addEventListener("keydown", function (e) {
      if (e.key === "Tab" && e.shiftKey && activeEl) {
        e.preventDefault();
        activeEl.focus();
      }
    });
    activeEl = el;
    positionPop(el);
  }

  function bindMark(el, info) {
    el._gloss = info;
    el.tabIndex = 0;
    el.addEventListener("mouseenter", function () {
      if (!coarse) showPop(el);
    });
    el.addEventListener("mouseleave", function (e) {
      if (coarse) return;
      if (relatedIsGlossUi(e.relatedTarget)) return;
      scheduleHide(HIDE_DELAY_MS);
    });
    el.addEventListener("focus", function () { showPop(el); });
    el.addEventListener("blur", function (e) {
      if (relatedIsGlossUi(e.relatedTarget)) return;
      scheduleHide(HIDE_DELAY_MS);
    });
    el.addEventListener("keydown", function (e) {
      if (e.key !== "Tab" || e.shiftKey) return;
      if (!pop || pop.style.display !== "block") return;
      var link = pop.querySelector(".jp-link");
      if (!link) return;
      e.preventDefault();
      link.focus();
    });
    el.addEventListener("click", function (e) {
      if (!coarse) return;
      e.stopPropagation();
      if (activeEl === el && pop && pop.style.display === "block") hidePop();
      else showPop(el);
    });
  }

  function buildIndex(payload) {
    var byLower = Object.create(null);
    var keys = [];
    Object.keys(payload || {}).forEach(function (abbr) {
      var row = payload[abbr] || {};
      var info = {
        term: row.term || abbr,
        expansion: row.expansion || row.full || "",
        layman: row.layman || row.def || "",
        id: row.id || String(abbr).replace(/ /g, "-")
      };
      function addKey(text) {
        if (!text) return;
        var t = String(text).trim();
        if (t.length < 2) return;
        var lk = t.toLowerCase();
        if (lk === "log" || lk === "all" || lk === "in") return;
        if (t.length === 2 && t.toLowerCase() !== String(abbr).toLowerCase()) return;
        if (byLower[lk]) return;
        byLower[lk] = info;
        keys.push(t);
      }
      addKey(abbr);
      (row.aliases || []).forEach(addKey);
      addKey(row.expansion || row.full);
    });
    keys.sort(function (a, b) { return b.length - a.length; });
    return { byLower: byLower, keys: keys };
  }

  function buildRegex(keys) {
    if (!keys.length) return null;
    var esc = keys.map(function (k) {
      return k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    });
    return new RegExp("(^|[^A-Za-z0-9])(" + esc.join("|") + ")(?![A-Za-z0-9])", "gi");
  }

  function processTextNode(node, byLower, re) {
    var text = node.nodeValue;
    re.lastIndex = 0;
    if (!re.test(text)) return;
    re.lastIndex = 0;

    var frag = document.createDocumentFragment();
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
      var pre = m[1], raw = m[2];
      var start = m.index + pre.length;
      if (start > last) frag.appendChild(document.createTextNode(text.slice(last, start)));
      var info = byLower[raw.toLowerCase()];
      if (!info) {
        frag.appendChild(document.createTextNode(raw));
      } else {
        var span = document.createElement("span");
        span.className = "gloss";
        span.textContent = raw;
        bindMark(span, info);
        frag.appendChild(span);
      }
      last = start + raw.length;
      if (re.lastIndex <= m.index) re.lastIndex = m.index + 1;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }

  function shouldSkip(el) {
    if (!el || el.nodeType !== 1) return false;
    if (SKIP_TAGS[el.nodeName]) return true;
    if (el.id === "jargon-pop") return true;
    if (el.closest && el.closest("#jargon-pop")) return true;
    if (el.classList && el.classList.contains("gloss")) return true;
    if (el.isContentEditable) return true;
    if (el.getAttribute && el.hasAttribute("data-no-gloss")) return true;
    return false;
  }

  function collectTextNodes(root) {
    if (!root) return [];
    if (root.nodeType === 3) return [root];
    if (root.nodeType !== 1) return [];
    if (shouldSkip(root)) return [];
    var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        var p = n.parentNode;
        while (p && p.nodeType === 1) {
          if (shouldSkip(p)) return NodeFilter.FILTER_REJECT;
          if (p.nodeName === "A") return NodeFilter.FILTER_REJECT;
          p = p.parentNode;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var nodes = [], n;
    while ((n = tw.nextNode())) nodes.push(n);
    return nodes;
  }

  var _re = null;
  var _byLower = null;

  function runOn(root) {
    if (!_re || !_byLower) return;
    collectTextNodes(root).forEach(function (node) {
      processTextNode(node, _byLower, _re);
    });
  }

  function observe() {
    if (!window.MutationObserver) return;
    var queued = [];
    var raf = 0;
    function flush() {
      raf = 0;
      var batch = queued;
      queued = [];
      batch.forEach(function (n) {
        if (!n || !n.parentNode) return;
        if (n.nodeType === 1 && shouldSkip(n)) return;
        if (n.parentNode.nodeType === 1 && shouldSkip(n.parentNode)) return;
        runOn(n);
      });
    }
    var obs = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type !== "childList") continue;
        for (var j = 0; j < m.addedNodes.length; j++) {
          var n = m.addedNodes[j];
          if (n.nodeType === 1 && (shouldSkip(n) || (n.classList && n.classList.contains("gloss")))) continue;
          if (n.id === "jargon-pop") continue;
          if (n.parentNode && n.parentNode.nodeType === 1 && shouldSkip(n.parentNode)) continue;
          queued.push(n);
        }
      }
      if (queued.length && !raf) raf = requestAnimationFrame(flush);
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  function bootMap(payload) {
    if (!payload || typeof payload !== "object") return;
    var idx = buildIndex(payload);
    if (!idx.keys.length) return;
    injectStyle();
    _byLower = idx.byLower;
    _re = buildRegex(idx.keys);
    runOn(document.body);
    observe();
    document.addEventListener("click", function (e) {
      if (!coarse) return;
      if (pop && pop.contains(e.target)) return;
      if (e.target && e.target.classList && e.target.classList.contains("gloss")) return;
      hidePop();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") hidePop();
    });
  }

  function boot() {
    if (window.__BOUNDRY_JARGON) {
      bootMap(window.__BOUNDRY_JARGON);
      return;
    }
    fetch("/api/acronyms", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (map) { if (map) bootMap(map); })
      .catch(function () {});
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
