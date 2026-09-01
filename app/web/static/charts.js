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

  function doughnut(id, labels, data, colors, p) {
    return new Chart(document.getElementById(id), {
      type: 'doughnut',
      data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderColor: cssVar('--bg') }] },
      options: opts(p, false),
    });
  }

  function render() {
    instances.forEach(function (c) { c.destroy(); });
    instances = [];
    var S = window.STATS || {};
    var p = palette();
    var sev3 = [p.sev.low, p.sev.medium, p.sev.high];

    instances.push(doughnut('c-severity', ['low', 'medium', 'high'],
      [S.severity.low, S.severity.medium, S.severity.high], sev3, p));

    var tlOpts = opts(p, true);
    tlOpts.plugins.zoom = {  // chartjs-plugin-zoom: wheel narrows/widens the time window
      zoom: { wheel: { enabled: true }, drag: { enabled: false }, mode: 'x' },
      pan: { enabled: true, mode: 'x' },
    };
    instances.push(new Chart(document.getElementById('c-timeline'), {
      type: 'line',
      data: {
        labels: S.timeline.labels,
        datasets: [
          { label: 'alerts', data: S.timeline.alerts, borderColor: p.accent, backgroundColor: p.accent, tension: 0.3 },
          { label: 'incidents', data: S.timeline.incidents, borderColor: p.sev.high, backgroundColor: p.sev.high, tension: 0.3 },
        ],
      },
      options: tlOpts,
    }));

    instances.push(sevBar('c-srcip', S.by_src_ip, p, 'src_ip'));
    instances.push(sevBar('c-host', S.by_host, p, 'host'));
    instances.push(sevBar('c-rule', S.by_rule, p, 'rule'));
    instances.push(sevBar('c-mitre', S.by_mitre, p, 'mitre'));  // -> incidents with a verdict tagged this technique
    instances.push(doughnut('c-verdicts', ['benign', 'suspicious', 'malicious'],
      [S.verdict_dist.benign, S.verdict_dist.suspicious, S.verdict_dist.malicious], sev3, p));
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
      rows = [['bucket', 'alerts', 'incidents']].concat(
        S.timeline.labels.map(function (l, i) { return [l, S.timeline.alerts[i], S.timeline.incidents[i]]; }));
    } else if (key === 'heatmap') {
      rows = [['weekday', 'hour', 'alerts']];
      S.heatmap.matrix.forEach(function (row, d) {
        row.forEach(function (c, h) { rows.push([S.heatmap.days[d], h, c]); });
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
