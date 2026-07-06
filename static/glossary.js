/* Boundry.AI — site-wide acronym hover tooltips.
   Fetches the acronym map and wraps known acronyms in the page text with an
   <abbr> that shows the full phrase + definition on hover.

   Safety:
   - matches only exact-case, standalone tokens (word boundaries) from the map
   - never touches inputs, code, links, buttons, or already-wrapped text
   - opt out of any subtree with data-no-gloss
   - runs once, after load. */
(function () {
  "use strict";

  var SKIP_TAGS = {
    SCRIPT: 1, STYLE: 1, A: 1, ABBR: 1, INPUT: 1, TEXTAREA: 1,
    BUTTON: 1, SELECT: 1, OPTION: 1, CODE: 1, PRE: 1, LABEL: 1
  };

  function buildRegex(keys) {
    keys.sort(function (a, b) { return b.length - a.length; }); // longest first
    var esc = keys.map(function (k) { return k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); });
    // capture a leading boundary char, the acronym, and require a trailing non-alnum
    return new RegExp("(^|[^A-Za-z0-9])(" + esc.join("|") + ")(?![A-Za-z0-9])", "g");
  }

  function processTextNode(node, map, re) {
    var text = node.nodeValue;
    re.lastIndex = 0;
    if (!re.test(text)) return;
    re.lastIndex = 0;

    var frag = document.createDocumentFragment();
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
      var pre = m[1], acr = m[2];
      var start = m.index + pre.length;
      if (start > last) frag.appendChild(document.createTextNode(text.slice(last, start)));
      var info = map[acr];
      var abbr = document.createElement("abbr");
      abbr.className = "gloss";
      abbr.title = info.full + (info.def ? " — " + info.def : "");
      abbr.textContent = acr;
      frag.appendChild(abbr);
      last = start + acr.length;
      if (re.lastIndex <= m.index) re.lastIndex = m.index + 1; // guard against stalls
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }

  function collectTextNodes(root) {
    var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        var p = n.parentNode;
        while (p && p.nodeType === 1) {
          if (SKIP_TAGS[p.nodeName]) return NodeFilter.FILTER_REJECT;
          if (p.hasAttribute && p.hasAttribute("data-no-gloss")) return NodeFilter.FILTER_REJECT;
          p = p.parentNode;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var nodes = [], n;
    while ((n = tw.nextNode())) nodes.push(n);
    return nodes;
  }

  function injectStyle() {
    if (document.getElementById("gloss-style")) return;
    var s = document.createElement("style");
    s.id = "gloss-style";
    s.textContent = "abbr.gloss{border-bottom:1px dotted #9944ee;cursor:help;text-decoration:none;}";
    document.head.appendChild(s);
  }

  function run(map) {
    var keys = Object.keys(map);
    if (!keys.length) return;
    injectStyle();
    var re = buildRegex(keys);
    collectTextNodes(document.body).forEach(function (node) {
      processTextNode(node, map, re);
    });
  }

  function boot() {
    fetch("/api/acronyms", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (map) { if (map) run(map); })
      .catch(function () {});
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
