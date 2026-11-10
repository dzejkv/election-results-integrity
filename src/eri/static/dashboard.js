// Public dashboard. Uses textContent only (never innerHTML) so nothing from
// the API can be interpreted as markup.
"use strict";

const $ = (id) => document.getElementById(id);
const fmt = new Intl.NumberFormat();

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderTotals(t) {
  $("election-name").textContent = t.name;
  $("election-id").textContent = t.election_id;
  $("updated").textContent = new Date(t.generated_at).toLocaleTimeString();
  $("reporting").textContent = `${t.stations_reporting} / ${t.stations_total}`;
  $("ballots").textContent = fmt.format(t.ballots_cast);
  $("invalid").textContent = fmt.format(t.invalid_ballots);
  $("review").textContent = fmt.format(t.results_under_review);

  const box = $("candidates");
  box.replaceChildren();
  const sorted = [...t.candidates].sort((a, b) => b.votes - a.votes);
  for (const c of sorted) {
    const row = el("div", "candidate");
    const head = el("div", "candidate-head");
    head.append(el("span", "name", c.name));
    head.append(el("span", "num", `${fmt.format(c.votes)} · ${(c.share * 100).toFixed(1)}%`));
    const track = el("div", "track");
    const bar = el("div", "bar");
    bar.style.width = `${(c.share * 100).toFixed(2)}%`;
    track.append(bar);
    row.append(head, track);
    box.append(row);
  }

  $("audit-head").textContent = t.audit.head_hash;
  $("audit-entries").textContent = fmt.format(t.audit.entries);
}

function renderStations(list) {
  const body = $("stations");
  body.replaceChildren();
  for (const s of list) {
    const tr = el("tr");
    tr.append(el("td", "mono", s.station_id), el("td", "", s.name),
              el("td", "num", fmt.format(s.registered_voters)));
    const td = el("td");
    td.append(el("span", `pill ${s.status}`, s.status.replace("_", " ")));
    tr.append(td);
    body.append(tr);
  }
}

function renderAudit(v) {
  const pill = $("audit-status");
  pill.textContent = v.ok ? "chain valid" : "CHAIN BROKEN";
  pill.className = `pill ${v.ok ? "reported" : "broken"}`;
}

async function refresh() {
  try {
    const [t, s, v] = await Promise.all(
      ["/api/totals", "/api/stations", "/api/audit/verify"].map((u) => fetch(u).then((r) => r.json()))
    );
    renderTotals(t);
    renderStations(s);
    renderAudit(v);
  } catch (err) {
    $("updated").textContent = "connection lost, retrying";
  }
}

refresh();
setInterval(refresh, 5000);
