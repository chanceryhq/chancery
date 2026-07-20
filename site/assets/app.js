/* Chancery landing page. No dependencies, no third-party requests. */
(function () {
  'use strict';
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ── sticky nav ─────────────────────────────────────── */
  var head = document.querySelector('header');
  var onScroll = function () {
    head.classList.toggle('stuck', window.scrollY > 8);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  /* ── scroll reveal ──────────────────────────────────── */
  var revealables = document.querySelectorAll('.rv');
  if (reduced || !('IntersectionObserver' in window)) {
    revealables.forEach(function (el) { el.classList.add('in'); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var el = e.target;
        // Stagger siblings so grids cascade instead of popping as a block.
        var delay = parseInt(el.dataset.delay || '0', 10);
        setTimeout(function () { el.classList.add('in'); }, delay);
        io.unobserve(el);
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.06 });
    revealables.forEach(function (el) { io.observe(el); });
  }

  /* ── copy-to-clipboard ──────────────────────────────── */
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.dataset.copy;
      var done = function () {
        var ico = btn.querySelector('.ico');
        var was = ico.textContent;
        btn.classList.add('done');
        ico.textContent = '✓';
        setTimeout(function () {
          btn.classList.remove('done');
          ico.textContent = was;
        }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () {});
      } else {
        // http / older browsers: hidden textarea fallback.
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:absolute;left:-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); done(); } catch (e) {}
        document.body.removeChild(ta);
      }
    });
  });

  /* ── tabs ───────────────────────────────────────────── */
  document.querySelectorAll('[data-tabs]').forEach(function (group) {
    var tabs = Array.prototype.slice.call(group.querySelectorAll('[role=tab]'));
    var select = function (i) {
      tabs.forEach(function (t, j) {
        var on = i === j;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
      });
    };
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { select(i); });
      t.addEventListener('keydown', function (e) {
        var d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        var next = (i + d + tabs.length) % tabs.length;
        select(next);
        tabs[next].focus();
      });
    });
    select(0);
  });

  /* ── hero terminal ──────────────────────────────────── */
  // The whole product in six commands: grant, allow, deny, revoke, deny again.
  var SCRIPT = [
    { cmd: 'chancery writ grant --to deploy-bot --cap "call:github/get_*" --ttl 8h' },
    { out: 'writ w_01K3MZQ4T8 · block b_01K3MZQ4TB · expires in 8h', cls: 'dim' },
    { gap: 1 },
    { cmd: 'chancery mcp wrap --agent deploy-bot --writ w_01K3MZQ4T8 -- npx @acme/github-mcp' },
    { out: 'listening · tools/list filtered to the writ', cls: 'dim' },
    { gap: 1 },
    { out: 'agent → github/get_pull_request', cls: 'dim', pre: '  ' },
    { out: 'ALLOW   forwarded · attributed · recorded', cls: 'ok', pre: '  ', tag: 5 },
    { out: 'agent → github/delete_repo', cls: 'dim', pre: '  ' },
    { out: 'DENY    never reached the server', cls: 'no', pre: '  ', tag: 4 },
    { gap: 1 },
    { cmd: 'chancery writ revoke w_01K3MZQ4T8' },
    { out: 'revoked — the delegation tree dies on the next call', cls: 'dim' },
    { gap: 1 },
    { out: 'agent → github/get_pull_request', cls: 'dim', pre: '  ' },
    { out: 'DENY    authority revoked · mid-session, no restart', cls: 'no', pre: '  ', tag: 4 }
  ];

  var body = document.getElementById('term-body');
  var replay = document.getElementById('replay');
  if (!body) return;
  var timers = [];
  var clearTimers = function () {
    timers.forEach(clearTimeout);
    timers = [];
  };
  var after = function (ms, fn) { timers.push(setTimeout(fn, ms)); };

  // Renders one line, optionally typing it out character by character.
  function line(step, done) {
    if (step.gap) {
      body.appendChild(document.createElement('br'));
      return done();
    }
    var el = document.createElement('div');
    el.className = step.cmd ? 'cmd' : (step.cls || '');
    body.appendChild(el);

    var text = step.cmd || ((step.pre || '') + step.out);

    if (!step.cmd) {
      // Output lines appear whole — only the human types.
      if (step.tag) {
        var t = document.createElement('span');
        t.className = 'tag';
        t.textContent = text.slice(0, (step.pre || '').length + step.tag);
        el.appendChild(t);
        el.appendChild(document.createTextNode(text.slice((step.pre || '').length + step.tag)));
      } else {
        el.textContent = text;
      }
      return after(step.cls === 'dim' ? 190 : 340, done);
    }

    var caret = document.createElement('span');
    caret.className = 'caret';
    el.appendChild(caret);
    var i = 0;
    (function type() {
      if (i >= text.length) {
        caret.remove();
        return after(420, done);
      }
      // Type in small bursts so long commands don't drag.
      var burst = Math.min(text.length - i, 2 + Math.floor(Math.random() * 3));
      caret.before(document.createTextNode(text.substr(i, burst)));
      i += burst;
      after(16 + Math.random() * 22, type);
    })();
  }

  function run() {
    clearTimers();
    body.textContent = '';
    var i = 0;
    (function next() {
      if (i >= SCRIPT.length) {
        if (replay) replay.hidden = false;
        return;
      }
      line(SCRIPT[i++], next);
    })();
  }

  function renderStatic() {
    body.textContent = '';
    SCRIPT.forEach(function (s) {
      if (s.gap) { body.appendChild(document.createElement('br')); return; }
      var el = document.createElement('div');
      el.className = s.cmd ? 'cmd' : (s.cls || '');
      el.textContent = s.cmd || ((s.pre || '') + s.out);
      body.appendChild(el);
    });
    if (replay) replay.hidden = true;
  }

  if (replay) {
    replay.hidden = true;
    replay.addEventListener('click', function () {
      replay.hidden = true;
      run();
    });
  }

  if (reduced) {
    renderStatic();
  } else if ('IntersectionObserver' in window) {
    // Start when the terminal is actually on screen, once.
    var tio = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting) return;
      tio.disconnect();
      run();
    }, { threshold: 0.25 });
    tio.observe(body);
  } else {
    run();
  }
})();
