/* Attestra UI: progressive enhancement for native <select> (Option M).
   The real <select> stays in the DOM (hidden, still submitted); this only adds a
   styled trigger + listbox and mirrors the choice back with a 'change' event. */
(function () {
  "use strict";
  var uid = 0, openInst = null;

  function txt(o) { return (o.label || o.textContent || "").trim(); }

  function Dropdown(sel) {
    this.sel = sel; this.id = "asel-" + (++uid); this.active = -1; this.query = ""; this.qt = 0;
    var w = this.wrap = document.createElement("div");
    w.className = "asel";
    var b = this.btn = document.createElement("button");
    b.type = "button"; b.className = "asel-trigger";
    b.setAttribute("role", "combobox"); b.setAttribute("aria-haspopup", "listbox");
    b.setAttribute("aria-expanded", "false"); b.setAttribute("aria-controls", this.id);
    if (sel.id) {
      var lab = document.querySelector('label[for="' + CSS.escape(sel.id) + '"]');
      if (lab) { if (!lab.id) lab.id = sel.id + "-label"; b.setAttribute("aria-labelledby", lab.id + " " + this.id + "-val"); }
    }
    b.innerHTML = '<span class="asel-value" id="' + this.id + '-val"></span><span class="asel-caret" aria-hidden="true"></span>';
    var pop = this.pop = document.createElement("div");
    pop.className = "asel-pop"; pop.hidden = true;
    if (sel.options.length > 8) {
      var s = this.search = document.createElement("input");
      s.type = "text"; s.className = "asel-search"; s.placeholder = "Search…"; s.setAttribute("aria-label", "Filter options");
      s.setAttribute("autocomplete", "off");
      pop.appendChild(s);
      var self0 = this;
      s.addEventListener("input", function () { self0.filter(s.value); });
      s.addEventListener("keydown", function (e) { self0.onKey(e, true); });
    }
    var ul = this.list = document.createElement("ul");
    ul.id = this.id; ul.className = "asel-list"; ul.setAttribute("role", "listbox"); ul.tabIndex = -1;
    pop.appendChild(ul);
    sel.parentNode.insertBefore(w, sel);
    w.appendChild(sel); w.appendChild(b); w.appendChild(pop);
    sel.classList.add("asel-native"); sel.tabIndex = -1; sel.setAttribute("aria-hidden", "true");
    sel.dataset.aselDone = "1";
    var self = this;
    b.addEventListener("click", function () { self.isOpen() ? self.close() : self.open(); });
    b.addEventListener("keydown", function (e) { self.onKey(e, false); });
    ul.addEventListener("mousedown", function (e) { e.preventDefault(); });
    ul.addEventListener("click", function (e) {
      var li = e.target.closest("li.asel-opt");
      if (li && !li.classList.contains("is-disabled")) { self.choose(+li.dataset.i); self.close(); self.btn.focus(); }
    });
    ul.addEventListener("mousemove", function (e) {
      var li = e.target.closest("li.asel-opt");
      if (li && !li.classList.contains("is-disabled")) self.setActive(+li.dataset.i, false);
    });
    sel.addEventListener("change", function () { self.sync(); });
    if (sel.form) sel.form.addEventListener("reset", function () { setTimeout(function () { self.sync(); }, 0); });
    new MutationObserver(function () { self.build(); self.sync(); })
      .observe(sel, { childList: true, subtree: true, attributes: true, attributeFilter: ["disabled", "selected", "label"] });
    this.build(); this.sync();
  }

  Dropdown.prototype.build = function () {
    var ul = this.list, sel = this.sel; ul.innerHTML = ""; this.items = [];
    var lastGroup = null;
    for (var i = 0; i < sel.options.length; i++) {
      var o = sel.options[i], g = o.parentNode.tagName === "OPTGROUP" ? o.parentNode : null;
      if (g && g !== lastGroup) {
        var gl = document.createElement("li"); gl.className = "asel-group"; gl.setAttribute("role", "presentation");
        gl.textContent = g.label; ul.appendChild(gl);
      }
      lastGroup = g;
      var li = document.createElement("li");
      li.className = "asel-opt"; li.id = this.id + "-o" + i; li.dataset.i = i;
      li.setAttribute("role", "option"); li.textContent = txt(o);
      if (o.disabled || (g && g.disabled)) { li.classList.add("is-disabled"); li.setAttribute("aria-disabled", "true"); }
      ul.appendChild(li); this.items.push(li);
    }
  };

  Dropdown.prototype.sync = function () {
    var sel = this.sel, i = sel.selectedIndex, o = sel.options[i];
    var v = this.btn.querySelector(".asel-value");
    v.textContent = o ? txt(o) : "";
    this.btn.classList.toggle("is-placeholder", !o || o.value === "");
    this.btn.disabled = sel.disabled;
    this.wrap.classList.toggle("is-disabled", sel.disabled);
    this.items.forEach(function (li, k) {
      li.setAttribute("aria-selected", k === i ? "true" : "false");
      li.classList.toggle("is-selected", k === i);
    });
  };

  Dropdown.prototype.isOpen = function () { return !this.pop.hidden; };

  Dropdown.prototype.open = function () {
    if (this.sel.disabled) return;
    if (openInst && openInst !== this) openInst.close();
    openInst = this;
    this.pop.hidden = false; this.wrap.classList.add("is-open");
    this.btn.setAttribute("aria-expanded", "true");
    if (this.search) { this.search.value = ""; this.filter(""); }
    this.place();
    this.setActive(this.sel.selectedIndex >= 0 ? this.sel.selectedIndex : this.next(-1, 1), true);
    if (this.search) this.search.focus();
  };

  Dropdown.prototype.close = function () {
    if (!this.isOpen()) return;
    this.pop.hidden = true; this.wrap.classList.remove("is-open", "flip-up");
    this.btn.setAttribute("aria-expanded", "false"); this.btn.removeAttribute("aria-activedescendant");
    if (openInst === this) openInst = null;
  };

  Dropdown.prototype.place = function () {
    this.wrap.classList.remove("flip-up");
    var r = this.btn.getBoundingClientRect(), h = Math.min(this.pop.scrollHeight, 320);
    var below = window.innerHeight - r.bottom, above = r.top;
    if (below < h + 16 && above > below) this.wrap.classList.add("flip-up");
  };

  Dropdown.prototype.visible = function (k) { var li = this.items[k]; return li && !li.hidden && !li.classList.contains("is-disabled"); };

  Dropdown.prototype.next = function (from, dir) {
    for (var k = from + dir; k >= 0 && k < this.items.length; k += dir) if (this.visible(k)) return k;
    return from;
  };

  Dropdown.prototype.setActive = function (k, scroll) {
    if (k < 0 || !this.items[k]) return;
    if (this.items[this.active]) this.items[this.active].classList.remove("is-active");
    this.active = k; var li = this.items[k]; li.classList.add("is-active");
    (this.search || this.btn).setAttribute("aria-activedescendant", li.id);
    if (scroll) li.scrollIntoView({ block: "nearest" });
  };

  Dropdown.prototype.choose = function (k) {
    if (!this.visible(k)) return;
    if (this.sel.selectedIndex !== k) {
      this.sel.selectedIndex = k;
      this.sel.dispatchEvent(new Event("input", { bubbles: true }));
      this.sel.dispatchEvent(new Event("change", { bubbles: true }));
    }
    this.sync();
  };

  Dropdown.prototype.filter = function (q) {
    q = q.trim().toLowerCase(); var first = -1, self = this;
    this.items.forEach(function (li, k) {
      li.hidden = q !== "" && li.textContent.toLowerCase().indexOf(q) < 0;
      if (first < 0 && self.visible(k)) first = k;
    });
    Array.prototype.forEach.call(this.list.querySelectorAll(".asel-group"), function (g) {
      var n = g.nextElementSibling, any = false;
      while (n && !n.classList.contains("asel-group")) { if (!n.hidden) any = true; n = n.nextElementSibling; }
      g.hidden = !any;
    });
    if (first >= 0) this.setActive(first, true);
  };

  Dropdown.prototype.typeahead = function (ch) {
    var self = this; clearTimeout(this.qt); this.query += ch.toLowerCase();
    this.qt = setTimeout(function () { self.query = ""; }, 600);
    for (var n = 0; n < this.items.length; n++) {
      var k = (this.active + (this.query.length === 1 ? 1 : 0) + n) % this.items.length;
      if (this.visible(k) && this.items[k].textContent.trim().toLowerCase().indexOf(this.query) === 0) return k;
    }
    return -1;
  };

  Dropdown.prototype.onKey = function (e, inSearch) {
    var open = this.isOpen(), k;
    switch (e.key) {
      case "ArrowDown": case "ArrowUp":
        e.preventDefault();
        if (!open) { this.open(); return; }
        this.setActive(this.next(this.active, e.key === "ArrowDown" ? 1 : -1), true); return;
      case "Home": case "End":
        if (!open || inSearch) return;
        e.preventDefault();
        this.setActive(e.key === "Home" ? this.next(-1, 1) : this.next(this.items.length, -1), true); return;
      case "Enter": case " ":
        if (e.key === " " && inSearch) return;
        e.preventDefault();
        if (!open) { this.open(); return; }
        this.choose(this.active); this.close(); this.btn.focus(); return;
      case "Escape":
        if (open) { e.preventDefault(); this.close(); this.btn.focus(); } return;
      case "Tab":
        if (open) { this.choose(this.active); this.close(); } return;
      default:
        if (!inSearch && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          k = this.typeahead(e.key);
          if (k >= 0) { if (open) this.setActive(k, true); else this.choose(k); }
        }
    }
  };

  function enhance(root) {
    var list = (root.querySelectorAll ? root : document).querySelectorAll("select:not([multiple]):not([data-native]):not([data-asel-done])");
    if (root.tagName === "SELECT" && !root.multiple && !root.dataset.aselDone && !root.hasAttribute("data-native")) new Dropdown(root);
    Array.prototype.forEach.call(list, function (s) { if (!s.dataset.aselDone && s.size <= 1) new Dropdown(s); });
  }

  document.addEventListener("mousedown", function (e) { if (openInst && !openInst.wrap.contains(e.target)) openInst.close(); });
  window.addEventListener("resize", function () { if (openInst) openInst.place(); });
  document.addEventListener("focusin", function (e) { if (openInst && !openInst.wrap.contains(e.target)) openInst.close(); });


  /* <details> used as menus (top nav "More", avatar menu, any details.topnav-more / [data-menu]):
     close on outside click and Esc (focus back to summary); opening one closes the others. */
  var MENU = "details.topnav-more, details.rail-menu, details[data-menu]";
  function menus() { return document.querySelectorAll(MENU); }
  document.addEventListener("toggle", function (e) {
    var d = e.target;
    if (!d.matches || !d.matches(MENU) || !d.open) return;
    Array.prototype.forEach.call(menus(), function (o) { if (o !== d && o.open && !o.contains(d)) o.open = false; });
  }, true);
  document.addEventListener("click", function (e) {
    Array.prototype.forEach.call(menus(), function (d) { if (d.open && !d.contains(e.target)) d.open = false; });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    Array.prototype.forEach.call(menus(), function (d) {
      if (d.open) { d.open = false; var s = d.querySelector("summary"); if (s && d.contains(document.activeElement)) s.focus(); }
    });
  });

  /* Login "Show/Hide" password toggle (the template's inline script is blocked by the CSP). */
  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("#toggle-pw");
    if (!btn) return;
    var input = document.getElementById("password");
    if (!input) return;
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.textContent = show ? "Hide" : "Show";
    btn.setAttribute("aria-pressed", show ? "true" : "false");
  });

  function init() {
    document.documentElement.classList.add("js-asel");
    enhance(document);
    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        Array.prototype.forEach.call(m.addedNodes, function (n) { if (n.nodeType === 1 && !n.closest(".asel")) enhance(n); });
      });
    }).observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();

/* Custom tooltips: replaces native title tooltips app-wide */
(function () {
  "use strict";
  var tip = null, cur = null, timer = null;
  function ensure() {
    if (!tip) { tip = document.createElement("div"); tip.className = "atip"; tip.setAttribute("role", "tooltip"); tip.id = "atip"; document.body.appendChild(tip); }
    return tip;
  }
  function find(el) {
    while (el && el !== document.body && el.nodeType === 1) {
      if (el.hasAttribute("title") && el.getAttribute("title").trim()) {
        el.setAttribute("data-tip", el.getAttribute("title")); el.removeAttribute("title");
      }
      if (el.hasAttribute("data-tip")) return el;
      el = el.parentElement;
    }
    return null;
  }
  function place(el) {
    var t = ensure(), r = el.getBoundingClientRect();
    t.textContent = el.getAttribute("data-tip");
    t.classList.remove("below"); t.style.left = "0px"; t.style.top = "0px"; t.classList.add("show");
    var w = t.offsetWidth, h = t.offsetHeight, vw = document.documentElement.clientWidth;
    var left = r.left + r.width / 2 - w / 2; left = Math.max(8, Math.min(left, vw - w - 8));
    var top = r.top - h - 10;
    if (top < 8) { top = r.bottom + 10; t.classList.add("below"); }
    t.style.left = (left + window.scrollX) + "px"; t.style.top = (top + window.scrollY) + "px";
    t.style.setProperty("--ax", (r.left + r.width / 2 - left) + "px");
    el.setAttribute("aria-describedby", "atip");
  }
  function show(el) { clearTimeout(timer); cur = el; timer = setTimeout(function () { if (cur === el) place(el); }, 250); }
  function hide() { clearTimeout(timer); if (cur) cur.removeAttribute("aria-describedby"); cur = null; if (tip) tip.classList.remove("show"); }
  document.addEventListener("mouseover", function (e) { var el = find(e.target); if (el !== cur) { hide(); if (el) show(el); } });
  document.addEventListener("mouseout", function (e) { if (cur && !cur.contains(e.relatedTarget)) hide(); });
  document.addEventListener("focusin", function (e) { var el = find(e.target); if (el) { hide(); cur = el; place(el); } });
  document.addEventListener("focusout", hide);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") hide(); });
  window.addEventListener("scroll", hide, true);
})();

/* Card header icons chosen from the heading text */
(function () {
  "use strict";
  var RULES = [
    [/signed authori|^authori/i, "pen"], [/target|scope|sites?\b|site grade/i, "target"],
    [/test plan|coverage|sampling/i, "clip"], [/automated scan|scan|asv|quarter/i, "radar"],
    [/import/i, "upload"], [/report|draft|writeup|statement of applic/i, "report"],
    [/severity|breakdown|by tool|score/i, "bars"], [/open findings by|findings|finding|nonconform|from findings/i, "bug"],
    [/passed|verified|integrity/i, "check"], [/calendar|scheduled/i, "cal"], [/history|events|audit log|pending/i, "clock"],
    [/share|link|token/i, "link"], [/people|users?\b|invite|recipient|client/i, "users"], [/comment/i, "chat"],
    [/badge|certificate|grade/i, "award"], [/how to fix|recommend|corrective/i, "wrench"], [/proof|evidence/i, "img"],
    [/risk/i, "warn"], [/setting|switch|layout|template/i, "gear"], [/segmentation|pci|frameworks?|compliance|iso/i, "layers"],
    [/library|description|details/i, "book"], [/engagement/i, "brief"], [/create|new|apply/i, "plus"]
  ];
  function pick(t) { for (var i = 0; i < RULES.length; i++) if (RULES[i][0].test(t)) return RULES[i][1]; return "doc"; }
  function run() {
    document.querySelectorAll(".card-head, .card > h2:first-child, .tile-head").forEach(function (el) {
      if (el.hasAttribute("data-ico")) return;
      var h = el.matches("h2") ? el : (el.querySelector("h2,h3") || el);
      el.setAttribute("data-ico", pick((h.textContent || "").trim()));
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run); else run();
})();
