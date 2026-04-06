/* OpsMon Dashboard UI (sem OTP) */
(function () {
  var KEY = 'opsmon_dashboard_token';
  var sortC = { k: 'name', d: 1 };
  var sortG = { k: 'name', d: 1 };
  var rowsC = [];
  var rowsG = [];
  var timer = null;

  function getToken() {
    try { return (sessionStorage.getItem(KEY) || '').trim(); } catch (e) { return ''; }
  }
  function setToken(v) {
    try { if (v) sessionStorage.setItem(KEY, v); else sessionStorage.removeItem(KEY); } catch (e) { /* noop */ }
  }
  function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function fmt(n) {
    var x = Number(n);
    if (!isFinite(x)) return '-';
    if (Math.abs(x) >= 1e6) return x.toExponential(2);
    return x % 1 === 0 ? String(x) : x.toFixed(2);
  }
  function fmtBytes(n) {
    var x = Number(n);
    if (!isFinite(x)) return '-';
    if (x >= 1e9) return (x / 1e9).toFixed(2) + ' GB';
    if (x >= 1e6) return (x / 1e6).toFixed(2) + ' MB';
    if (x >= 1e3) return (x / 1e3).toFixed(1) + ' kB';
    return Math.round(x) + ' B';
  }
  function labelsHtml(labels) {
    if (!labels || typeof labels !== 'object' || !Object.keys(labels).length) return '<span class="tag">{}</span>';
    return Object.keys(labels).sort().map(function (k) { return '<span class="tag">' + esc(k) + '=' + esc(labels[k]) + '</span>'; }).join('');
  }
  function authHeaders() {
    var raw = getToken();
    if (!raw) return {};
    if (/^[A-Za-z0-9._-]+$/.test(raw) && raw.length < 2000 && raw.indexOf('ey') !== 0) return { 'X-API-Key': raw };
    var tok = raw.toLowerCase().indexOf('bearer ') === 0 ? raw.slice(7).trim() : raw;
    return { Authorization: 'Bearer ' + tok };
  }
  function statusPill(health) {
    var el = document.getElementById('status-pill');
    if (!el) return;
    var text = ((health && (health.status || health.overall)) || 'unknown').toString().toLowerCase();
    el.classList.remove('ok', 'warn', 'err');
    var label = 'Unknown';
    if (text === 'healthy' || text === 'ok') { el.classList.add('ok'); label = 'Healthy'; }
    else if (text === 'unhealthy' || text === 'error') { el.classList.add('err'); label = 'Error'; }
    else { el.classList.add('warn'); label = text; }
    el.querySelector('span:last-child').textContent = label;
  }

  function sortRows(rows, s) {
    var out = rows.slice();
    out.sort(function (a, b) {
      var va = s.k === 'value' ? Number(a.value) : (s.k === 'labels' ? JSON.stringify(a.labels || {}) : String(a.name));
      var vb = s.k === 'value' ? Number(b.value) : (s.k === 'labels' ? JSON.stringify(b.labels || {}) : String(b.name));
      if (va < vb) return -s.d;
      if (va > vb) return s.d;
      return 0;
    });
    return out;
  }
  function filtered(rows) {
    var q = ((document.getElementById('filter') || {}).value || '').trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(function (r) { return String(r.name).toLowerCase().indexOf(q) >= 0; });
  }
  function renderTable(id, rows, sort) {
    var body = document.getElementById(id);
    if (!body) return;
    var list = sortRows(filtered(rows), sort);
    body.textContent = '';
    if (!list.length) {
      var emptyTr = document.createElement('tr');
      var emptyTd = document.createElement('td');
      emptyTd.colSpan = 3;
      emptyTd.textContent = 'sem séries';
      emptyTr.appendChild(emptyTd);
      body.appendChild(emptyTr);
      return;
    }
    list.forEach(function (r) {
      var tr = document.createElement('tr');
      var tdName = document.createElement('td');
      tdName.className = 'mono';
      tdName.textContent = String(r.name);

      var tdLabels = document.createElement('td');
      var tags = document.createElement('div');
      tags.className = 'tags';
      var labels = (r && r.labels && typeof r.labels === 'object') ? r.labels : {};
      var keys = Object.keys(labels).sort();
      if (!keys.length) {
        var emptyTag = document.createElement('span');
        emptyTag.className = 'tag';
        emptyTag.textContent = '{}';
        tags.appendChild(emptyTag);
      } else {
        keys.forEach(function (k) {
          var tag = document.createElement('span');
          tag.className = 'tag';
          tag.textContent = String(k) + '=' + String(labels[k]);
          tags.appendChild(tag);
        });
      }
      tdLabels.appendChild(tags);

      var tdValue = document.createElement('td');
      tdValue.className = 'value mono';
      tdValue.textContent = fmt(r.value);

      tr.appendChild(tdName);
      tr.appendChild(tdLabels);
      tr.appendChild(tdValue);
      body.appendChild(tr);
    });
  }
  function redrawTables() {
    renderTable('tbl-c', rowsC, sortC);
    renderTable('tbl-g', rowsG, sortG);
    document.getElementById('meta-c').textContent = String(filtered(rowsC).length) + ' / ' + String(rowsC.length);
    document.getElementById('meta-g').textContent = String(filtered(rowsG).length) + ' / ' + String(rowsG.length);
  }

  function drawSeries(canvasId, points, field, fallback, color) {
    var c = document.getElementById(canvasId);
    if (!c) return;
    var ctx = c.getContext('2d');
    var dpr = window.devicePixelRatio || 1;
    var w = c.clientWidth || 600;
    var h = 260;
    c.width = Math.floor(w * dpr);
    c.height = Math.floor(h * dpr);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    ctx.fillStyle = '#0d1014';
    ctx.fillRect(0, 0, w, h);
    if (!points || !points.length) return;

    var values = points.map(function (p) {
      if (p[field] && typeof p[field] === 'object') {
        return Object.keys(p[field]).reduce(function (acc, k) { return acc + Number(p[field][k] || 0); }, 0);
      }
      return Number(p[fallback] || 0);
    });
    var min = Math.min.apply(null, values);
    var max = Math.max.apply(null, values);
    if (!isFinite(min) || !isFinite(max)) return;
    if (max === min) { min -= 1; max += 1; }
    var pad = { l: 40, r: 10, t: 10, b: 20 };
    var gw = w - pad.l - pad.r;
    var gh = h - pad.t - pad.b;
    function x(i) { return pad.l + (gw * i) / Math.max(1, points.length - 1); }
    function y(v) { return pad.t + gh - ((v - min) / (max - min)) * gh; }

    ctx.strokeStyle = '#2a2d33';
    for (var i = 0; i <= 3; i++) {
      var yy = pad.t + (gh * i) / 3;
      ctx.beginPath(); ctx.moveTo(pad.l, yy); ctx.lineTo(w - pad.r, yy); ctx.stroke();
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    values.forEach(function (v, i) {
      if (i === 0) ctx.moveTo(x(i), y(v));
      else ctx.lineTo(x(i), y(v));
    });
    ctx.stroke();
  }

  function load() {
    var tenant = ((document.getElementById('tenant') || {}).value || 'default').trim() || 'default';
    var url = '/opsmon/dashboard/snapshot?tenant_id=' + encodeURIComponent(tenant);
    fetch(url, { headers: { Accept: 'application/json', ...authHeaders() } })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
        return r.json();
      })
      .then(function (j) {
        document.getElementById('ts').textContent = 'ts: ' + (j.timestamp || '-');
        document.getElementById('health-json').textContent = JSON.stringify(j.health || {}, null, 2);
        document.getElementById('raw-json').textContent = JSON.stringify(j, null, 2);
        statusPill(j.health || {});

        rowsC = (j.runtime_metrics && j.runtime_metrics.counters) || [];
        rowsG = (j.runtime_metrics && j.runtime_metrics.gauges) || [];
        redrawTables();

        var series = (j.chart_series && j.chart_series.points) || [];
        drawSeries('chart-counters', series, 'counter_by_name', 'counter_sum', '#a855f7');
        drawSeries('chart-gauges', series, 'gauge_by_name', 'gauge_avg', '#73bf69');

        var last = series.length ? series[series.length - 1] : null;
        document.getElementById('stat-csum').textContent = last ? fmt(last.counter_sum) : '-';
        document.getElementById('stat-gavg').textContent = last ? fmt(last.gauge_avg) : '-';
        var cpu = rowsG.find(function (x) { return x.name === 'process_cpu_percent'; });
        var rss = rowsG.find(function (x) { return x.name === 'process_memory_rss_bytes'; });
        document.getElementById('stat-cpu').textContent = cpu ? fmt(cpu.value) + ' %' : '-';
        document.getElementById('stat-rss').textContent = rss ? fmtBytes(rss.value) : '-';
      })
      .catch(function (e) {
        document.getElementById('raw-json').textContent = 'Erro: ' + e.message;
      });
  }

  function setAutoRefresh() {
    if (timer) { clearInterval(timer); timer = null; }
    var sec = parseInt((document.getElementById('interval') || {}).value || '0', 10);
    if (sec > 0) timer = setInterval(load, sec * 1000);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var t = getToken();
    if (t) document.getElementById('token').value = t;
    document.getElementById('save').addEventListener('click', function () {
      setToken(((document.getElementById('token') || {}).value || '').trim());
      load();
    });
    document.getElementById('load').addEventListener('click', load);
    document.getElementById('interval').addEventListener('change', setAutoRefresh);
    document.getElementById('filter').addEventListener('input', redrawTables);
    Array.prototype.forEach.call(document.querySelectorAll('th[data-sort]'), function (th) {
      th.addEventListener('click', function () {
        var tId = th.parentElement.parentElement.nextElementSibling.id;
        var st = tId === 'tbl-c' ? sortC : sortG;
        var key = th.getAttribute('data-sort');
        st.d = st.k === key ? -st.d : 1;
        st.k = key;
        redrawTables();
      });
    });
    setAutoRefresh();
    load();
  });
})();
