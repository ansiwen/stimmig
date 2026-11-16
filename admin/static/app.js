"use strict";
const $ = (id) => document.getElementById(id);
const TEMPLATE = {
  title: "Board election",
  receipt_mode: "full",
  tally: { candidates: ["A", "B", "C"], method: "schulze", seats: 1 },
  schedule: { registration_close: "", voting_open: "", voting_close: "" },
};
let token = "";
let current = "";

function say(text) { $("status").textContent = text; $("error").hidden = true; }
function fail(text) { $("error").textContent = text; $("error").hidden = false; }

async function api(method, path, body) {
  const res = await fetch("/api" + path, {
    method,
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* no body */ }
  if (res.status === 401) { signOut(); throw new Error("Wrong or missing token."); }
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// run shows what a call does and what it answered.
async function run(label, fn) {
  say(label + "…");
  try { await fn(); } catch (e) { fail(label + " failed: " + e.message); return false; }
  return true;
}

function signOut() {
  token = "";
  try { sessionStorage.removeItem("token"); } catch (e) { /* private mode */ }
  $("app").hidden = true; $("signout").hidden = true; $("login").hidden = false;
}

function cell(row, text) { const td = document.createElement("td"); td.textContent = text; row.appendChild(td); }

async function refresh() {
  const list = (await api("GET", "/elections")).elections;
  const body = $("elections");
  body.replaceChildren();
  for (const e of list) {
    const id = e.id;
    const row = document.createElement("tr");
    row.tabIndex = 0;
    cell(row, e.title); cell(row, e.phase + (e.tallied ? ", tallied" : "")); cell(row, id);
    const open = () => select(id);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } });
    body.appendChild(row);
  }
  if (current) await show();
}

const STEPS = [
  ["close-registration", "Close the registration", "registration"],
  ["open-voting", "Open the voting", "registration closed"],
  ["close-voting", "Close the voting", "registration closed"],
  ["tally", "Publish the key and the result", "closing"],
];

async function select(id) { current = id; await show(); $("detail").scrollIntoView(); }

async function show() {
  const st = await api("GET", "/elections/" + current);
  $("detail").hidden = false;
  const facts = $("facts");
  facts.replaceChildren();
  const add = (k, v) => {
    const dt = document.createElement("dt"), dd = document.createElement("dd");
    dt.textContent = k; dd.textContent = v; facts.append(dt, dd);
  };
  add("Title", st.title); add("ID", st.id); add("Phase of the log", st.phase);
  add("Eligible / issued / cast", st.eligible + " / " + st.issued + " / " + st.cast);
  add("Method", st.method + ", " + st.seats + " seat(s), " + st.candidates.join(", "));
  add("Different ballots possible", st.possible_ballots);
  if (st.schedule) add("Schedule", JSON.stringify(st.schedule));
  $("roll-box").hidden = st.phase !== "setup";
  const steps = $("steps");
  steps.replaceChildren();
  for (const [step, label, phase] of STEPS) {
    // The services check the order; the page offers the step that comes next.
    const b = document.createElement("button");
    b.type = "button"; b.textContent = label;
    b.disabled = st.phase !== phase;
    b.addEventListener("click", () => act(step, label));
    steps.appendChild(b);
  }
  $("winners").textContent = st.result ? "Winners: " + (st.result.winners || []).join(", ") + (st.result.tie ? " (unresolved tie between " + st.result.tie.candidates.join(", ") + ")" : "") : "";
}

async function act(step, label) {
  if (!confirm(label + "? This cannot be undone.")) return;
  if (await run(label, () => api("POST", "/elections/" + current + "/" + step))) { await run("Reload", refresh); say(label + ": done."); }
}

$("roll").addEventListener("click", async () => {
  let warning = "";
  if (await run("Publish the roll", async () => {
    warning = (await api("PUT", "/elections/" + current + "/roll", { voters: $("voters").value })).warning;
  })) { await run("Reload", refresh); say("The roll is published." + (warning ? " Warning: " + warning : "")); }
});

function definition() {
  try { return JSON.parse($("definition").value); } catch (e) { fail("The definition is not valid JSON: " + e.message); return null; }
}

// Times are typed in RFC 3339; a mistake is reported by the server.
$("preview").addEventListener("click", async () => {
  const def = definition(); if (!def) return;
  await run("Check", async () => { say("The definition is valid; " + (await api("POST", "/preview", def)).possible_ballots + " different ballots are possible."); });
});
$("create").addEventListener("click", async () => {
  const def = definition(); if (!def) return;
  let id = "";
  if (await run("Create the election", async () => { id = (await api("POST", "/elections", def)).id; })) {
    current = id; await run("Reload", refresh); say("Election created: " + id + ". Next: publish the roll.");
  }
});

async function start(t) {
  token = t;
  if (!await run("Sign in", refresh)) { signOut(); return; }
  try { sessionStorage.setItem("token", t); } catch (e) { /* private mode */ }
  $("login").hidden = true; $("app").hidden = false; $("signout").hidden = false; say("");
}
$("signin").addEventListener("click", () => start($("token").value));
$("token").addEventListener("keydown", (ev) => { if (ev.key === "Enter") start($("token").value); });
$("signout").addEventListener("click", signOut);
$("definition").value = JSON.stringify(TEMPLATE, null, 2);
let saved = "";
try { saved = sessionStorage.getItem("token") || ""; } catch (e) { /* private mode */ }
if (saved) start(saved); else $("login").hidden = false;
