/* Builds the incidents-page charts from window.STATS. Re-renders on `themechange`
   so colors track the active [data-theme]. Panel titles live in the HTML card-head.
   Needs Chart.js loaded first. */
(function () {
  var instances = [];
  if (window.ChartZoom && window.Chart) { try { Chart.register(window.ChartZoom); } catch (e) {} }

  // Read theme colors straight from the CSS vars — base.html's inline <style> is
  // the single source of truth for the brand palette; no fallbacks to drift.
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function palette() {
    return {
      text: cssVar('--text'),
      grid: cssVar('--border'),
      accent: cssVar('--accent'),
      sev: { low: cssVar('--sev-low'), medium: cssVar('--sev-medium'), high: cssVar('--sev-high') },
    };
  }

  function opts(p, withScales) {
    var o = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: p.text, boxWidth: 12 } } },
    };
    if (withScales) {
      o.scales = {
        x: { ticks: { color: p.text }, grid: { color: p.grid }, beginAtZero: true },
        y: { ticks: { color: p.text }, grid: { color: p.grid }, beginAtZero: true },
      };
    }
    return o;
  }

  // Horizontal bar of [label, count, severity] rows; bar color = severity bucket.
  // filterKey set -> clicking a bar filters the incidents list by that field.
  function sevBar(id, rows, p, filterKey) {
    var o = opts(p, true);
    o.indexAxis = 'y';
    o.plugins.legend.display = false;
    // fixed label gutter so truncated ticks never clip against the panel edge
    o.scales.y.afterFit = function (scale) { scale.width = Math.max(scale.width, 150); };
    o.scales.y.ticks.callback = function (v) {
      var s = this.getLabelForValue(v);
      return s.length > 24 ? s.slice(0, 23) + '…' : s;
    };
    o.plugins.tooltip = { callbacks: { title: function (items) { return items[0].label; } } };
    if (filterKey) {
      o.onClick = function (evt, els) {
        if (!els.length) return;
        var label = String(rows[els[0].index][0]).split(' ')[0];  // rule_id / ip / host / technique
        var u = new URL(location.href);                 // keep the active time range
        u.searchParams.set(filterKey, label);
        u.searchParams.delete('dow');
        u.searchParams.delete('hour');
        location.href = u.pathname + u.search;
      };
      o.onHover = function (evt, els) {
        evt.native.target.style.cursor = els.length ? 'pointer' : 'default';
      };
    }
    return new Chart(document.getElementById(id), {
      type: 'bar',
      data: {
        labels: rows.map(function (r) { return r[0]; }),
        datasets: [{
          data: rows.map(function (r) { return r[1]; }),
          backgroundColor: rows.map(function (r) { return p.sev[r[2]]; }),
        }],
      },
      options: o,
    });
  }

  // filterKey set -> clicking a slice filters the incidents list by that field
  function doughnut(id, labels, data, colors, p, filterKey) {
    var o = opts(p, false);
    if (filterKey) {
      o.onClick = function (evt, els) {
        if (!els.length) return;
        var u = new URL(location.href);                 // keep the active time range
        u.searchParams.set(filterKey, labels[els[0].index]);
        u.searchParams.delete('dow');
        u.searchParams.delete('hour');
        location.href = u.pathname + u.search;
      };
      o.onHover = function (evt, els) {
        evt.native.target.style.cursor = els.length ? 'pointer' : 'default';
      };
    }
    return new Chart(document.getElementById(id), {
      type: 'doughnut',
      data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderColor: cssVar('--bg') }] },
      options: o,
    });
  }

  // ---- time-bucketed views, built in the VIEWER'S LOCAL ZONE from S.events -----
  // S.events = [[epoch_ms, incident_id | 0], ...] ascending. new Date(ms) is local,
  // so getHours()/getDay() bucket by the day/hour the viewer actually sees.
  var HM_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  function buildTimeline(events) {
    if (!events.length) return { labels: [], alerts: [], incidents: [] };
    var first = events[0][0], last = events[events.length - 1][0];
    var fine = last - first < 3 * 3600e3;                 // burst -> 5-min bins, else hourly
    var step = fine ? 5 * 60e3 : 3600e3;
    function floor(ms) {
      var d = new Date(ms);
      d.setSeconds(0, 0);
      d.setMinutes(fine ? d.getMinutes() - (d.getMinutes() % 5) : 0);
      return d.getTime();
    }
    var start = floor(first), end = floor(last), buckets = [], t;
    for (t = start; t <= end; t += step) buckets.push(t);
    var pos = {}; buckets.forEach(function (b, i) { pos[b] = i; });
    var alerts = buckets.map(function () { return 0; });
    var incs = buckets.map(function () { return {}; });
    events.forEach(function (e) {
      var i = pos[floor(e[0])];
      alerts[i]++;
      if (e[1]) incs[i][e[1]] = 1;
    });
    var fmt = fine
      ? { hour: '2-digit', minute: '2-digit' }
      : { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' };
    return {
      labels: buckets.map(function (ms) { return new Date(ms).toLocaleString([], fmt); }),
      alerts: alerts,
      incidents: incs.map(function (s) { return Object.keys(s).length; }),
    };
  }

  function buildHeatmap(events) {
    var m = HM_DAYS.map(function () { return new Array(24).fill(0); }), peak = 0;
    events.forEach(function (e) {
      var d = new Date(e[0]);
      m[(d.getDay() + 6) % 7][d.getHours()]++;            // getDay 0=Sun -> Mon=0
    });
    m.forEach(function (row) { row.forEach(function (c) { if (c > peak) peak = c; }); });
    return { matrix: m, max: peak };
  }

  function renderHeatmap(hm) {
    var host = document.getElementById('c-heatmap');
    if (!host) return;
    var base = new URL(location.href);
    base.searchParams.set('tzmin', new Date().getTimezoneOffset());  // let the server bucket local too
    var h, d, out = '<span class="hm-corner"></span>';
    for (h = 0; h < 24; h++) out += '<span class="hm-hour">' + String(h).padStart(2, '0') + '</span>';
    for (d = 0; d < 7; d++) {
      out += '<span class="hm-day">' + HM_DAYS[d] + '</span>';
      for (h = 0; h < 24; h++) {
        var c = hm.matrix[d][h];
        var pct = hm.max && c ? 8 + Math.round(c * 92 / hm.max) : 0;
        var u = new URL(base);
        u.searchParams.set('dow', d);
        u.searchParams.set('hour', h);
        out += '<a class="hm-cell" href="' + u.pathname + u.search + '"'
          + ' title="' + HM_DAYS[d] + ' ' + String(h).padStart(2, '0') + ':00 — ' + c + ' alert(s)"'
          + ' style="background: color-mix(in srgb, var(--accent) ' + pct + '%, transparent);"></a>';
      }
    }
    host.innerHTML = out;
  }

  function render() {
    instances.forEach(function (c) { c.destroy(); });
    instances = [];
    var S = window.STATS || {};
    var p = palette();
    var sev3 = [p.sev.low, p.sev.medium, p.sev.high];

    instances.push(doughnut('c-severity', ['low', 'medium', 'high'],
      [S.severity.low, S.severity.medium, S.severity.high], sev3, p, 'severity'));

    var tl = buildTimeline(S.events || []);
    renderHeatmap(buildHeatmap(S.events || []));

    var tlOpts = opts(p, true);
    tlOpts.plugins.zoom = {  // chartjs-plugin-zoom: wheel narrows/widens the time window
      zoom: { wheel: { enabled: true }, drag: { enabled: false }, mode: 'x' },
      pan: { enabled: true, mode: 'x' },
    };
    // incidents/bucket (~1-3) would vanish against alerts/bucket (100s) on one axis
    tlOpts.scales.y.title = { display: true, text: 'alerts', color: p.text };
    tlOpts.scales.y1 = {
      position: 'right', beginAtZero: true,
      ticks: { color: p.text, precision: 0 },
      grid: { drawOnChartArea: false },
      title: { display: true, text: 'incidents', color: p.text },
    };
    instances.push(new Chart(document.getElementById('c-timeline'), {
      type: 'line',
      data: {
        labels: tl.labels,
        datasets: [
          { label: 'alerts', data: tl.alerts, borderColor: p.accent, backgroundColor: p.accent, tension: 0.3 },
          { label: 'incidents', data: tl.incidents, borderColor: p.sev.high, backgroundColor: p.sev.high, tension: 0.3, yAxisID: 'y1' },
        ],
      },
      options: tlOpts,
    }));

    instances.push(sevBar('c-srcip', S.by_src_ip, p, 'src_ip'));
    instances.push(sevBar('c-host', S.by_host, p, 'host'));
    instances.push(sevBar('c-rule', S.by_rule, p, 'rule'));
    instances.push(sevBar('c-mitre', S.by_mitre, p, 'mitre'));  // -> incidents with a verdict tagged this technique
    instances.push(doughnut('c-verdicts', ['benign', 'suspicious', 'malicious'],
      [S.verdict_dist.benign, S.verdict_dist.suspicious, S.verdict_dist.malicious], sev3, p, 'verdict'));
  }

  // --- panel "⋯" -> download that panel's data as CSV -------------------------
  function csvCell(v) {
    v = String(v);
    return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  }

  function exportCsv(key) {
    var S = window.STATS || {}, rows;
    if (key === 'severity' || key === 'verdict_dist') {
      var keys = key === 'severity' ? ['low', 'medium', 'high'] : ['benign', 'suspicious', 'malicious'];
      rows = [[key === 'severity' ? 'severity' : 'verdict', 'count']].concat(
        keys.map(function (k) { return [k, S[key][k]]; }));
    } else if (key === 'timeline') {
      var t = buildTimeline(S.events || []);
      rows = [['bucket', 'alerts', 'incidents']].concat(
        t.labels.map(function (l, i) { return [l, t.alerts[i], t.incidents[i]]; }));
    } else if (key === 'heatmap') {
      rows = [['weekday', 'hour', 'alerts']];
      buildHeatmap(S.events || []).matrix.forEach(function (row, d) {
        row.forEach(function (c, h) { rows.push([HM_DAYS[d], h, c]); });
      });
    } else {
      rows = [['label', 'count', 'severity']].concat(S[key] || []);
    }
    var blob = new Blob([rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n')],
      { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = key + '.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  document.querySelectorAll('.card-menu[data-stat]').forEach(function (btn) {
    btn.addEventListener('click', function () { exportCsv(btn.dataset.stat); });
  });

  // zoom reset: button + double-click on the chart
  function resetZoom(id) {
    var c = Chart.getChart(id);
    if (c && c.resetZoom) c.resetZoom();
  }
  document.querySelectorAll('.zoom-reset[data-chart]').forEach(function (btn) {
    btn.addEventListener('click', function () { resetZoom(btn.dataset.chart); });
  });
  var tl = document.getElementById('c-timeline');
  if (tl) tl.addEventListener('dblclick', function () { resetZoom('c-timeline'); });

  render();
  window.addEventListener('themechange', render);
})();
