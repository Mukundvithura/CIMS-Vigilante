"use strict";
// Vigilante front end: a single page over the CIMS JSON API.
// Every value from the server goes through html`` which HTML-escapes it (XSS defence, SR-07).
// The UI only hides actions a role can't use; the server re-checks every request (SR-02).

const $ = (sel, root = document) => root.querySelector(sel);
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);
const raw = (s) => ({ __html: s });
const val = (v) => (v == null || v === false ? "" : v.__html !== undefined ? v.__html : Array.isArray(v) ? v.map(val).join("") : esc(v));
const html = (strings, ...vals) => raw(strings.reduce((out, s, i) => out + s + (i < vals.length ? val(vals[i]) : ""), ""));
const mount = (el, tpl) => { el.innerHTML = tpl.__html; };

const STATUSES = ["NEW", "TRIAGED", "ASSIGNED", "INVESTIGATING", "RESOLVED", "CLOSED"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const STAGE_HINT = { NEW: "awaiting triage", TRIAGED: "awaiting assignment", ASSIGNED: "not yet started", INVESTIGATING: "under investigation", RESOLVED: "awaiting closure", CLOSED: "investigation closed" };
// Stages where the signed-in role is the one who acts next (highlighted on the custody strip).
const YOUR_MOVE = { ANALYST: ["NEW", "ASSIGNED", "INVESTIGATING"], MANAGER: ["TRIAGED", "RESOLVED"] };
const ROLES = ["REPORTER", "ANALYST", "MANAGER", "ADMIN", "AUDITOR"];
const INCIDENT_ROLES = ["REPORTER", "ANALYST", "MANAGER"];
const NAV = {
  dashboard: { label: "Dashboard", icon: "grid_view", roles: INCIDENT_ROLES },
  incidents: { label: "Incidents", icon: "warning", roles: INCIDENT_ROLES },
  users: { label: "User Management", icon: "manage_accounts", roles: ["ADMIN"] },
  audit: { label: "Audit Log", icon: "history_toggle_off", roles: ["AUDITOR"] },
};
// Mirror of incidents.TRANSITIONS on the server, used only to decide which buttons to show.
const TRANSITIONS = [
  { from: "ASSIGNED", to: "INVESTIGATING", role: "ANALYST", label: "Start investigation", icon: "play_arrow", cls: "btn-primary" },
  { from: "INVESTIGATING", to: "RESOLVED", role: "ANALYST", label: "Mark resolved", icon: "task_alt", cls: "btn-primary" },
  { from: "RESOLVED", to: "CLOSED", role: "MANAGER", label: "Close incident", icon: "lock", cls: "btn-ok", reason: true },
  { from: "RESOLVED", to: "INVESTIGATING", role: "MANAGER", label: "Reopen", icon: "replay", cls: "btn-danger", reason: true },
];
const MAX_EVIDENCE = 5 * 1024 * 1024;

let me = null;        // {id, username, role} from /me
let cache = [];       // incidents visible to this user
let page = "";
let query = "";
let statusFilter = "ACTIVE";

// ---------- helpers ----------
const incId = (id) => `INC-${String(id).padStart(4, "0")}`;
const who = (id) => (id == null ? "—" : id === me.id ? "you" : `user #${id}`);
const when = (ts) => (ts ? new Date(ts).toLocaleString() : "");
function ago(ts) {
  const s = (Date.now() - new Date(ts)) / 1000;
  if (Number.isNaN(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const sevBadge = (s) => (s
  ? html`<span class="badge sev-${s}"><span class="dot ${s === "CRITICAL" ? "dot-ping" : ""}"></span>${s}</span>`
  : html`<span class="badge sev-NONE">UNRATED</span>`);
const statusBadge = (s) => html`<span class="badge status st-${s}">${s}</span>`;
const isOpen = (i) => i.status !== "CLOSED";
const canSeeIncidents = () => INCIDENT_ROLES.includes(me.role);
const home = () => (me.role === "ADMIN" ? "#/users" : me.role === "AUDITOR" ? "#/audit" : "#/dashboard");
const scopeText = () => ({
  REPORTER: "Showing the incidents you reported.",
  ANALYST: "Showing incidents awaiting triage and incidents assigned to you (need-to-know).",
  MANAGER: "Showing every incident in the organisation.",
}[me.role]);
// Widths are set through the CSSOM because the CSP blocks inline style attributes.
const applyWidths = (root) => root.querySelectorAll("[data-w]").forEach((el) => { el.style.width = `${el.dataset.w}%`; });
const pct = (n, total) => (total ? Math.round((n / total) * 100) : 0);

async function api(path, { json, form } = {}) {
  const opts = { method: json || form ? "POST" : "GET", credentials: "same-origin", headers: { Accept: "application/json" } };
  if (json) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(json); }
  if (form) opts.body = form;
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "/login") {
    showLogin(me ? "Your session has expired. Please sign in again." : "");
    throw new Error("session expired");
  }
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

let toastTimer;
function toast(msg, ok = true) {
  const t = $("#toast");
  mount(t, html`<span class="ms" aria-hidden="true">${ok ? "check_circle" : "error"}</span><span>${msg}</span>`);
  t.className = `toast ${ok ? "ok" : "err"}`;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
}

// ---------- session ----------
function showLogin(msg = "") {
  me = null;
  cache = [];
  $("#shell").hidden = true;
  $("#login").hidden = false;
  $("#login-form").reset();
  $("#login-error").textContent = msg;
  $("#login-form [name=username]").focus();
}

async function start() {
  me = await api("/me");
  $("#login").hidden = true;
  $("#shell").hidden = false;
  $("#user-name").textContent = me.username;
  $("#user-role").textContent = me.role;
  $("#user-avatar").textContent = me.username.slice(0, 2).toUpperCase();
  $(".topbar").hidden = !canSeeIncidents(); // search + report only make sense for incident roles
  if (!location.hash || location.hash === "#/") location.hash = home();
  else route();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const btn = e.target.querySelector("button");
  btn.disabled = true;
  $("#login-error").textContent = "";
  try {
    await api("/login", { json: { username: f.get("username").trim(), password: f.get("password") } });
    await start();
  } catch (err) {
    $("#login-error").textContent = err.message === "invalid credentials" ? "Invalid username or password." : err.message;
  } finally {
    btn.disabled = false;
  }
});

$("#logout").addEventListener("click", async () => {
  await api("/logout", { json: {} }).catch(() => {});
  history.replaceState(null, "", "/");
  showLogin();
});

// ---------- routing ----------
async function route() {
  if (!me) return;
  const [, p = "", arg] = location.hash.split("/");
  page = p;
  renderNav();
  const view = $("#view");
  try {
    if (p === "dashboard" && canSeeIncidents()) await dashboard(view);
    else if (p === "incidents" && canSeeIncidents()) await incidentList(view);
    else if (p === "incident" && canSeeIncidents() && /^\d+$/.test(arg)) await incidentDetail(view, Number(arg));
    else if (p === "users" && me.role === "ADMIN") usersView(view);
    else if (p === "audit" && me.role === "AUDITOR") await auditView(view);
    else { location.hash = home(); return; }
    applyWidths(view);
  } catch (err) {
    if (me) mount(view, html`<section class="card empty"><span class="ms" aria-hidden="true">error</span>${err.message}</section>`);
  }
}

function renderNav() {
  const active = page === "incident" ? "incidents" : page;
  const crit = cache.filter((i) => i.severity === "CRITICAL" && isOpen(i)).length;
  mount($("#nav"), html`${Object.entries(NAV).filter(([, n]) => n.roles.includes(me.role)).map(([key, n]) => html`
    <a href="#/${key}" class="${key === active ? "active" : ""}"><span class="ms" aria-hidden="true">${n.icon}</span>${n.label}${
      key === "incidents" && crit ? html`<span class="count" title="Open critical incidents">${crit}</span>` : ""}</a>`)}`);
}

async function loadIncidents() {
  cache = await api("/incidents");
  renderNav();
}

// ---------- dashboard ----------
async function dashboard(view) {
  await loadIncidents();
  const count = (f) => cache.filter(f).length;
  const open = cache.filter(isOpen);
  const crit = open.filter((i) => i.severity === "CRITICAL").sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  const hot = crit[0];
  const queue = [...open].sort((a, b) => (SEV_RANK[a.severity] ?? 4) - (SEV_RANK[b.severity] ?? 4) || b.updated_at.localeCompare(a.updated_at)).slice(0, 8);

  mount(view, html`
  <section class="page-head">
    <div>
      <div class="title"><h1>Security Operations</h1>
        <span class="mono dim">Synced ${new Date().toLocaleTimeString()}</span></div>
      <p>${scopeText()}</p>
    </div>
  </section>

  <nav class="custody" aria-label="Incidents by lifecycle stage">${STATUSES.map((s) => {
    const n = count((i) => i.status === s);
    const move = n > 0 && YOUR_MOVE[me.role]?.includes(s);
    return html`<a class="cbox ${move ? "move" : ""} ${n ? "" : "zero"}" href="#/incidents" data-status="${s}">
      <span class="line"><span class="n">${n}</span><span class="stage">${s[0] + s.slice(1).toLowerCase()}</span></span>
      <span class="hint">${STAGE_HINT[s]}${move ? html`<b class="yours"> · you</b>` : ""}</span></a>`;
  })}</nav>

  ${hot ? html`
  <section class="alert">
    <div class="alert-main">
      <div>
        <div class="inline">${sevBadge("CRITICAL")}<span class="id">${incId(hot.id)}</span>${statusBadge(hot.status)}
          <span class="mono dim">updated ${ago(hot.updated_at)}</span></div>
        <p class="alert-title">${hot.title}</p>
        <p class="mid">Assignee: ${hot.assignee_id == null ? "unassigned" : who(hot.assignee_id)}${crit.length > 1 ? ` · ${crit.length - 1} more critical open` : ""}</p>
      </div>
    </div>
    <a class="btn btn-primary" href="#/incident/${hot.id}">Investigate<span class="ms" aria-hidden="true">arrow_forward</span></a>
  </section>` : html`
  <section class="alert ok">
    <div class="alert-main">
      <div><p class="alert-title">No open critical incidents</p><p class="mid">Nothing needs immediate escalation.</p></div>
    </div>
  </section>`}

  <section class="grid split form">
    <div class="card">
      <div class="card-head"><div class="card-title"><h2>Active queue</h2>
        <span class="badge">${open.length} open</span></div><a href="#/incidents">View all</a></div>
      ${incidentTable(queue, true)}
    </div>
    <div class="card">
      <div class="card-head"><h2>Open by severity</h2></div>
      ${severityBar(open)}
    </div>
  </section>`);
}

function severityBar(open) {
  const groups = [...SEVERITIES, "UNRATED"].map((s) => ({ s, n: open.filter((i) => (i.severity || "UNRATED") === s).length }));
  return html`
    <div class="sevbar" role="img" aria-label="${groups.map((g) => `${g.s} ${g.n}`).join(", ")}">${groups.filter((g) => g.n).map((g) => html`
      <span class="fill-${g.s}" data-w="${(g.n / open.length) * 100}"></span>`)}</div>
    <div class="legend">${groups.map((g) => html`
      <div class="legend-row"><span class="sw fill-${g.s}"></span>${g.s === "UNRATED" ? "Unrated" : g.s[0] + g.s.slice(1).toLowerCase()}
        <span class="n">${g.n}</span><span class="p">${pct(g.n, open.length)}%</span></div>`)}</div>`;
}

// ---------- incident list ----------
async function incidentList(view) {
  await loadIncidents();
  mount(view, html`
  <section class="page-head">
    <div><div class="title"><h1>Incidents</h1><span class="badge">${cache.length} visible</span></div><p>${scopeText()}</p></div>
  </section>
  <section class="card">
    <div class="card-head">
      <div class="chips" id="status-chips" role="group" aria-label="Filter by status">${["ACTIVE", "ALL", ...STATUSES].map((s) => html`
        <button type="button" data-status="${s}" class="${s === statusFilter ? "on" : ""}" aria-pressed="${s === statusFilter}">${s}</button>`)}</div>
    </div>
    <div id="incident-table"></div>
  </section>`);
  $("#status-chips").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    statusFilter = b.dataset.status;
    $("#status-chips").querySelectorAll("button").forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-pressed", x === b); });
    drawTable();
  });
  drawTable();
}

const matches = (i) => !query || [incId(i.id), i.title, i.status, i.severity || "unrated"].some((v) => v.toLowerCase().includes(query));

function drawTable() {
  const el = $("#incident-table");
  if (!el) return;
  const byStatus = (i) => statusFilter === "ALL" || (statusFilter === "ACTIVE" ? isOpen(i) : i.status === statusFilter);
  mount(el, incidentTable(cache.filter((i) => byStatus(i) && matches(i))));
}

function incidentTable(rows, compact = false) {
  if (!rows.length) return html`<div class="empty"><span class="ms" aria-hidden="true">inbox</span>No incidents to show.</div>`;
  return html`<div class="table-wrap"><table>
    <thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th>${compact ? "" : html`<th>Assignee</th><th>Updated</th>`}</tr></thead>
    <tbody>${rows.map((i) => html`
      <tr class="clickable" data-href="#/incident/${i.id}">
        <td class="id"><a href="#/incident/${i.id}">${incId(i.id)}</a></td>
        <td><div class="cell-title">${i.title}</div><div class="sub-line">Reported by ${who(i.reporter_id)}</div></td>
        <td>${sevBadge(i.severity)}</td>
        <td>${statusBadge(i.status)}</td>
        ${compact ? "" : html`<td class="mono">${i.assignee_id == null ? html`<span class="dim">Unassigned</span>` : who(i.assignee_id)}</td>
        <td class="mono dim" title="${when(i.updated_at)}">${ago(i.updated_at)}</td>`}
      </tr>`)}</tbody></table></div>`;
}

// ---------- incident detail ----------
async function incidentDetail(view, id) {
  const inc = await api(`/incidents/${id}`);
  const staff = me.role === "ANALYST" || me.role === "MANAGER";
  const mine = me.role === "MANAGER" || (me.role === "ANALYST" && inc.assignee_id === me.id);
  const workable = mine && !["NEW", "TRIAGED", "CLOSED"].includes(inc.status);
  const moves = TRANSITIONS.filter((t) => t.from === inc.status && t.role === me.role && mine);
  const canClassify = staff && ["NEW", "TRIAGED"].includes(inc.status);
  const canAssign = me.role === "MANAGER" && ["TRIAGED", "ASSIGNED"].includes(inc.status);
  const idx = STATUSES.indexOf(inc.status);

  mount(view, html`
  <section class="page-head">
    <div>
      <div class="inline">${sevBadge(inc.severity)}${statusBadge(inc.status)}</div>
      <p class="detail-id">${incId(inc.id)}</p>
      <h1 class="detail-title">${inc.title}</h1>
      <p>Reported by ${who(inc.reporter_id)} · ${when(inc.created_at)} · updated ${ago(inc.updated_at)}</p>
    </div>
    <a class="btn btn-ghost" href="#/incidents"><span class="ms" aria-hidden="true">arrow_back</span>All incidents</a>
  </section>

  <div>
    <ol class="custody case" aria-label="Lifecycle">${STATUSES.map((s, i) => {
      const state = i < idx || inc.status === "CLOSED" ? "done" : i === idx ? "now" : "todo";
      return html`<li class="cbox ${state}" ${state === "now" ? raw('aria-current="step"') : ""}>
        <span class="line"><span class="stage">${s[0] + s.slice(1).toLowerCase()}</span>${state === "done" ? html`<span class="ms" aria-label="complete">check</span>` : ""}</span>
        <span class="signer">${state === "todo" ? html`<span class="hint">pending</span>` : signer(s, inc)}</span></li>`;
    })}</ol>
    ${inc.status === "CLOSED" ? html`
    <p class="closed-note"><span class="ms" aria-hidden="true">lock</span><span><b>Investigation closed.</b> This record is read-only; its history stays in the audit log.</span></p>` : ""}
  </div>

  <div class="grid split-detail form">
    <div class="grid">
      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">description</span><h2>Summary</h2></div></div>
        <div class="desc">${inc.description}</div>
      </section>

      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">history_edu</span><h2>Sequence of events</h2>
          <span class="badge">${inc.notes.length + 1}</span></div><span class="sub">Entries cannot be edited once added</span></div>
        <ol class="timeline">
          <li class="tl-item">
            <div class="tl-body"><span class="tl-who">${who(inc.reporter_id)}</span><p class="tl-text mid">Incident reported</p></div>
            <time class="tl-time" datetime="${inc.created_at}">${when(inc.created_at)}</time></li>
          ${inc.notes.map((n) => html`
          <li class="tl-item">
            <div class="tl-body"><span class="tl-who">${who(n.author_id)}</span><p class="tl-text">${n.note}</p></div>
            <time class="tl-time" datetime="${n.created_at}">${when(n.created_at)}</time></li>`)}
        </ol>
        ${workable ? html`
        <form class="actions" data-form="note" data-id="${inc.id}">
          <label class="field"><span class="meta">Add an entry</span>
            <textarea name="note" rows="3" maxlength="5000" required placeholder="Findings, IOCs, containment steps…"></textarea></label>
          <div><button class="btn btn-primary btn-sm"><span class="ms" aria-hidden="true">add_comment</span>Add to record</button></div>
        </form>` : ""}
      </section>
    </div>

    <div class="grid">
      ${staff ? html`
      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">tune</span><h2>Actions</h2></div><span class="badge">${me.role}</span></div>
        <div class="actions">
          ${canClassify ? html`
          <form class="action-group" data-form="classify" data-id="${inc.id}">
            <span class="meta">Classify severity</span>
            <div class="row">
              <select name="severity" required aria-label="Severity">${SEVERITIES.map((s) => html`
                <option value="${s}" ${s === inc.severity ? "selected" : ""}>${s}</option>`)}</select>
              <button class="btn btn-primary"><span class="ms" aria-hidden="true">rule</span>Set severity</button>
            </div>
          </form>` : ""}
          ${canAssign ? html`
          <form class="action-group" data-form="assign" data-id="${inc.id}">
            <span class="meta">Assign to analyst</span>
            <div class="row">
              <input name="assignee_id" type="number" min="1" step="1" required placeholder="Analyst user ID" aria-label="Analyst user ID">
              <button class="btn btn-primary"><span class="ms" aria-hidden="true">person_add</span>Assign</button>
            </div>
          </form>` : ""}
          ${moves.length ? html`
          <form class="action-group" data-form="status" data-id="${inc.id}">
            <span class="meta">Update status</span>
            ${moves.some((m) => m.reason) ? html`
              <input name="reason" maxlength="200" required placeholder="Reason (recorded in the audit log)" aria-label="Reason">` : ""}
            <div class="row">${moves.map((m) => html`
              <button class="btn ${m.cls}" name="to" value="${m.to}"><span class="ms" aria-hidden="true">${m.icon}</span>${m.label}</button>`)}</div>
          </form>` : ""}
          ${!canClassify && !canAssign && !moves.length ? html`
          <p class="hint"><span class="ms" aria-hidden="true">info</span>${inc.status === "CLOSED"
            ? "This incident is closed and read-only."
            : me.role === "ANALYST" && inc.assignee_id !== me.id ? "Only the assigned analyst can progress this incident."
            : "No action available for your role at this stage."}</p>` : ""}
        </div>
      </section>` : html`
      <section class="card"><p class="hint card-pad"><span class="ms" aria-hidden="true">info</span>You can follow the progress of your report here. The security team will update its status.</p></section>`}

      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">fingerprint</span><h2>Evidence</h2>
          <span class="badge">${inc.evidence.length}</span></div><span class="sub">Fingerprinted with SHA-256 when filed</span></div>
        <div class="evidence">
          ${inc.evidence.length ? inc.evidence.map((ev, n) => html`
          <div class="ev-item">
            <div class="ev-main">
              <span class="ev-no">Exhibit ${n + 1}</span>
              <span class="ev-name">${ev.filename} <span class="dim">${(ev.size / 1024).toFixed(1)} KB</span></span>
              <span class="ev-by">Filed by ${who(ev.uploaded_by)} · ${when(ev.uploaded_at)}</span>
              <span class="ev-seal"><span class="meta">SHA-256</span><span class="hash" title="SHA-256">${ev.sha256}</span></span>
            </div>
            ${staff ? html`<button class="btn btn-ghost btn-sm" type="button" data-verify="${ev.id}"><span class="ms" aria-hidden="true">verified</span>Verify</button>` : ""}
            <span class="ev-result" id="ev-result-${ev.id}" role="status"></span>
          </div>`) : html`<p class="hint"><span class="ms" aria-hidden="true">info</span>No evidence attached yet.</p>`}
        </div>
        ${workable ? html`
        <form class="actions" data-form="evidence" data-id="${inc.id}">
          <label class="field"><span class="meta">Attach evidence (max 5 MB)</span><input name="file" type="file" required></label>
          <div><button class="btn btn-primary btn-sm"><span class="ms" aria-hidden="true">upload_file</span>Upload &amp; hash</button></div>
        </form>` : ""}
      </section>

      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">info</span><h2>Details</h2></div></div>
        <dl class="kv">
          <dt>Incident</dt><dd class="mono">${incId(inc.id)}</dd>
          <dt>Severity</dt><dd>${inc.severity || "unrated"}</dd>
          <dt>Status</dt><dd>${inc.status}</dd>
          <dt>Reporter</dt><dd>${who(inc.reporter_id)}</dd>
          <dt>Assignee</dt><dd>${inc.assignee_id == null ? "unassigned" : who(inc.assignee_id)}</dd>
          <dt>Created</dt><dd class="mono">${when(inc.created_at)}</dd>
          <dt>Updated</dt><dd class="mono">${when(inc.updated_at)}</dd>
        </dl>
      </section>
    </div>
  </div>`);
}

// Who held the record at each stage, from the incident itself (the full trail lives in the audit log).
function signer(stage, inc) {
  if (stage === "NEW") return `reported by ${who(inc.reporter_id)}`;
  if (stage === "TRIAGED") return "severity set";
  if (stage === "CLOSED") return "closed by manager";
  return inc.assignee_id == null ? "unassigned" : who(inc.assignee_id);
}

// ---------- admin ----------
function usersView(view) {
  const roleSelect = html`<select name="role" required aria-label="Role">${ROLES.map((r) => html`<option value="${r}">${r}</option>`)}</select>`;
  mount(view, html`
  <section class="page-head">
    <div><div class="title"><h1>User Management</h1><span class="badge">ADMIN</span></div>
      <p>Create accounts, change roles and unlock locked accounts. Administrators cannot see incident content (need-to-know).</p></div>
  </section>
  <div class="grid split-even">
    <section class="card">
      <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">person_add</span><h2>Create user</h2></div></div>
      <form class="actions" data-form="createUser">
        <label class="field"><span class="meta">Username</span><input name="username" minlength="3" maxlength="32" pattern="[A-Za-z0-9_.]+" required placeholder="letters, digits, _ or ."></label>
        <label class="field"><span class="meta">Password</span><input name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required placeholder="at least 12 characters"></label>
        <label class="field"><span class="meta">Role</span>${roleSelect}</label>
        <div><button class="btn btn-primary"><span class="ms" aria-hidden="true">add</span>Create user</button></div>
      </form>
    </section>
    <div class="grid">
      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">admin_panel_settings</span><h2>Change role</h2></div></div>
        <form class="actions" data-form="changeRole">
          <div class="row">
            <label class="field"><span class="meta">User ID</span><input name="user_id" type="number" min="1" step="1" required></label>
            <label class="field"><span class="meta">New role</span>${roleSelect}</label>
          </div>
          <p class="hint"><span class="ms" aria-hidden="true">shield_lock</span>You cannot change your own role (privilege-escalation guard). Every change is audited.</p>
          <div><button class="btn btn-primary"><span class="ms" aria-hidden="true">sync_alt</span>Change role</button></div>
        </form>
      </section>
      <section class="card">
        <div class="card-head"><div class="card-title"><span class="ms" aria-hidden="true">lock_open</span><h2>Unlock account</h2></div></div>
        <form class="actions" data-form="unlock">
          <p class="hint"><span class="ms" aria-hidden="true">info</span>Accounts lock after 5 failed sign-ins.</p>
          <div class="row">
            <label class="field"><span class="meta">User ID</span><input name="user_id" type="number" min="1" step="1" required></label>
            <button class="btn btn-ghost"><span class="ms" aria-hidden="true">lock_open</span>Unlock</button>
          </div>
        </form>
      </section>
    </div>
  </div>`);
}

// ---------- auditor ----------
const ALERT_ACTIONS = /FAILED|DENIED|LOCKED|TAMPERED|BROKEN/;

async function auditView(view) {
  const rows = await api("/audit");
  mount(view, html`
  <section class="page-head">
    <div><div class="title"><h1>Audit Log</h1><span class="badge">${rows.length} entries</span></div>
      <p>Append-only, SHA-256 hash-chained record of every security-relevant action (latest 500 shown).</p></div>
    <button class="btn btn-primary" type="button" data-verify-chain><span class="ms" aria-hidden="true">link</span>Verify chain integrity</button>
  </section>
  <div id="chain-result"></div>
  <section class="card">
    ${rows.length ? html`<div class="table-wrap"><table>
      <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Hash chain</th></tr></thead>
      <tbody>${rows.map((r) => html`<tr>
        <td class="mono dim">${r.id}</td>
        <td class="mono" title="${r.ts}">${when(r.ts)}</td>
        <td class="nowrap">${r.actor_id == null ? "system" : who(r.actor_id)}</td>
        <td class="nowrap ${ALERT_ACTIONS.test(r.action) ? "act-alert" : ""}">${r.action[0] + r.action.slice(1).toLowerCase().replaceAll("_", " ")}</td>
        <td>${r.target}${r.details ? html`<span class="target-detail">${r.details}</span>` : ""}</td>
        <td class="hash" title="prev ${r.prev_hash} | hash ${r.hash}"><span class="chain">${String(r.prev_hash || "").slice(0, 8)}<span class="ms" aria-hidden="true">arrow_forward</span>${r.hash.slice(0, 8)}</span></td>
      </tr>`)}</tbody></table></div>` : html`<div class="empty"><span class="ms" aria-hidden="true">history</span>No audit entries yet.</div>`}
  </section>`);
}

// ---------- shared event handling (one listener each; no inline handlers, CSP-safe) ----------
const formHandlers = {
  async classify(f, form) {
    await api(`/incidents/${form.dataset.id}/classify`, { json: { severity: f.get("severity") } });
    return "Severity set. Incident is now TRIAGED.";
  },
  async assign(f, form) {
    await api(`/incidents/${form.dataset.id}/assign`, { json: { assignee_id: Number(f.get("assignee_id")) } });
    return "Incident assigned.";
  },
  async status(f, form, submitter) {
    const to = submitter.value;
    const json = { status: to };
    if (f.get("reason")) json.reason = f.get("reason");
    await api(`/incidents/${form.dataset.id}/status`, { json });
    return `Status changed to ${to}.`;
  },
  async note(f, form) {
    await api(`/incidents/${form.dataset.id}/notes`, { json: { note: f.get("note") } });
    return "Note added to the record.";
  },
  async evidence(f, form) {
    const file = f.get("file");
    if (!file || !file.size) throw new Error("Choose a file to upload.");
    if (file.size > MAX_EVIDENCE) throw new Error("File exceeds 5 MB.");
    const body = new FormData();
    body.append("file", file);
    const r = await api(`/incidents/${form.dataset.id}/evidence`, { form: body });
    return `Evidence stored. SHA-256 ${r.sha256.slice(0, 16)}…`;
  },
  async createUser(f) {
    const r = await api("/admin/users", { json: { username: f.get("username"), password: f.get("password"), role: f.get("role") } });
    return `User #${r.id} created.`;
  },
  async changeRole(f) {
    await api(`/admin/users/${Number(f.get("user_id"))}/role`, { json: { role: f.get("role") } });
    return "Role changed.";
  },
  async unlock(f) {
    await api(`/admin/users/${Number(f.get("user_id"))}/unlock`, { json: {} });
    return "Account unlocked.";
  },
};

$("#view").addEventListener("submit", async (e) => {
  const form = e.target;
  const handler = formHandlers[form.dataset.form];
  if (!handler) return;
  e.preventDefault();
  const buttons = form.querySelectorAll("button");
  buttons.forEach((b) => { b.disabled = true; });
  try {
    toast(await handler(new FormData(form), form, e.submitter));
    await route();
  } catch (err) {
    toast(err.message, false);
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
});

$("#view").addEventListener("click", async (e) => {
  const row = e.target.closest("tr[data-href]");
  if (row && !e.target.closest("a, button")) { location.hash = row.dataset.href; return; }
  const stage = e.target.closest("a.cbox[data-status]");
  if (stage) { statusFilter = stage.dataset.status; return; } // the link itself navigates to the filtered list

  const verify = e.target.closest("[data-verify]");
  if (verify) {
    verify.disabled = true;
    try {
      const r = await api(`/evidence/${verify.dataset.verify}/verify`);
      const out = $(`#ev-result-${r.evidence_id}`);
      out.className = `ev-result finding ${r.intact ? "" : "bad"}`;
      mount(out, r.intact
        ? html`<span class="ms" aria-hidden="true">verified</span><span><b>Finding:</b> file is unchanged. Its SHA-256 matches the one recorded when it was filed.</span>`
        : html`<span class="ms" aria-hidden="true">gpp_bad</span><span><b>Finding: tampered.</b> Stored file hash is ${r.actual_sha256 ? r.actual_sha256.slice(0, 16) + "…" : "missing"}.</span>`);
    } catch (err) { toast(err.message, false); } finally { verify.disabled = false; }
    return;
  }

  const chain = e.target.closest("[data-verify-chain]");
  if (chain) {
    chain.disabled = true;
    try {
      const r = await api("/audit/verify");
      mount($("#chain-result"), r.intact ? html`
        <section class="alert ok verdict"><div class="alert-main">
          <div><p class="alert-title">Audit chain intact</p><p class="mid">Every entry's hash links to the one before it. No edits, inserts or deletions detected.</p></div></div>
</section>` : html`
        <section class="alert"><div class="alert-main">
          <div><p class="alert-title">Chain broken at entry #${r.first_bad_id}</p><p class="mid">The log was modified outside the application. A critical security event was raised.</p></div></div>
</section>`);
    } catch (err) { toast(err.message, false); } finally { chain.disabled = false; }
  }
});

$("#search").addEventListener("input", (e) => {
  query = e.target.value.trim().toLowerCase();
  if (page !== "incidents") location.hash = "#/incidents";
  else drawTable();
});

$("#report-btn").addEventListener("click", () => {
  $("#report-form").reset();
  $("#report-form .form-error").textContent = "";
  $("#report-dialog").showModal();
});

$("#report-form").addEventListener("submit", async (e) => {
  if (e.submitter?.value !== "submit") return; // Cancel / X close the dialog natively
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await api("/incidents", { json: { title: f.get("title"), description: f.get("description") } });
    $("#report-dialog").close();
    toast(`${incId(r.id)} reported.`);
    location.hash = `#/incident/${r.id}`;
  } catch (err) {
    $("#report-form .form-error").textContent = err.message;
  }
});

window.addEventListener("hashchange", route);
start().catch(() => showLogin());
