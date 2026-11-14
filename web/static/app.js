// Voting client. All cryptography and all protocol steps run in the
// WebAssembly module (stimmigInfo, stimmigBegin, stimmigComplete,
// stimmigCast, stimmigCheck); this file is the interface around it.
'use strict';

const T = {
  en: {
    loading: 'Loading and verifying the election…',
    missing: 'This link is incomplete. It must name the election, the log and the registrar.',
    phase: 'Phase: {0}. Eligible: {1}, credentials issued: {2}, ballots published: {3}.',
    trustTitle: 'What this election protects and what it does not',
    trust1: 'Your ballot cannot be linked to you as long as the registrar and the ballot box do not work together.',
    trust2: 'The operator holds the election key until the close and is trusted not to read ballots earlier.',
    trust3: 'This device and this page must be trustworthy. A receipt lets you prove how you voted, also to others.',
    trust4: 'After the close, all ballots are public and anyone can recompute the result.',
    registerTitle: '1. Get your voting credential',
    registerText: 'You log in at the registrar once. It signs your credential without seeing it, so your ballot stays anonymous. A lost credential cannot be issued again: keep this browser, or make a backup below.',
    begin: 'Get voting credential',
    loginLink: 'Log in at the registrar (opens a new tab)',
    loginCode: 'After the login, the registrar asks for this confirmation code:',
    loginWait: 'Keep this page open. It continues when you have logged in.',
    waiting: 'Waiting for your login…',
    haveCredential: 'You have your voting credential. Your entry in the public roll is {0}.',
    voteTitle: '2. Rank the candidates',
    rules: 'You may use up to {0} ranks.',
    rulesEqual: ' Several candidates may share a rank.',
    ranked: 'Your ranking, best first',
    rankedEmpty: 'No candidate ranked yet.',
    unranked: 'Not ranked',
    unrankedText: 'Candidates you do not rank count as tied below all ranked ones. Choose a candidate to add it to the end of your ranking.',
    add: 'Rank {0}',
    up: 'Move {0} up', down: 'Move {0} down', remove: 'Remove {0} from the ranking',
    tie: 'Same rank as the candidate above',
    tooManyRanks: 'You have used all {0} ranks.',
    review: 'Review ballot',
    confirmTitle: '3. Confirm your ballot',
    confirmUnranked: 'Not ranked, counted below all ranked: {0}.',
    confirmEmpty: 'You rank no candidate. This is an empty ballot.',
    confirmText: 'A cast ballot cannot be changed.',
    cast: 'Cast ballot', change: 'Change ranking',
    casting: 'Encrypting and casting your ballot…',
    doneTitle: 'Your ballot is cast',
    doneFull: 'The ballot box signed a receipt, which is stored in this browser. After the close you can check here that your ballot is in the public log.',
    doneNone: 'This election issues no receipts. This browser has deleted your credential and your ballot.',
    check: 'Check my ballot',
    checking: 'Verifying the public log…',
    notPublished: 'The log verifies. The ballots are published at the close; check again then.',
    included: 'Your ballot is in the public log.',
    decrypted: 'It was decrypted as: {0}',
    invalid: 'It is marked invalid: {0}',
    winners: 'Winners: {0}',
    backupTitle: 'Backup',
    backupText: 'Save your credential, ballot and receipt in a file encrypted with a passphrase, or load such a file to continue on this device.',
    passphrase: 'Passphrase (8 characters or more)',
    export: 'Save backup file',
    import: 'Load backup file',
    imported: 'Backup loaded.',
    badPassphrase: 'The passphrase is too short, or it does not open this file.',
  },
  de: {
    loading: 'Die Wahl wird geladen und geprüft…',
    missing: 'Dieser Link ist unvollständig. Er muss die Wahl, das Log und die Registrierstelle nennen.',
    phase: 'Phase: {0}. Wahlberechtigt: {1}, ausgegebene Berechtigungen: {2}, veröffentlichte Stimmzettel: {3}.',
    trustTitle: 'Was diese Wahl schützt und was nicht',
    trust1: 'Ihr Stimmzettel lässt sich nicht mit Ihnen verknüpfen, solange Registrierstelle und Urne nicht zusammenarbeiten.',
    trust2: 'Der Betreiber hält den Wahlschlüssel bis zum Schluss der Wahl und darf Stimmzettel nicht vorher lesen. Darauf wird vertraut.',
    trust3: 'Dieses Gerät und diese Seite müssen vertrauenswürdig sein. Mit einer Quittung können Sie auch anderen beweisen, wie Sie gewählt haben.',
    trust4: 'Nach dem Schluss sind alle Stimmzettel öffentlich, und jeder kann das Ergebnis nachrechnen.',
    registerTitle: '1. Wahlberechtigung holen',
    registerText: 'Sie melden sich einmal bei der Registrierstelle an. Sie signiert Ihre Berechtigung, ohne sie zu sehen; so bleibt Ihr Stimmzettel anonym. Eine verlorene Berechtigung wird nicht neu ausgestellt: Behalten Sie diesen Browser, oder legen Sie unten eine Sicherung an.',
    begin: 'Wahlberechtigung holen',
    loginLink: 'Bei der Registrierstelle anmelden (öffnet einen neuen Tab)',
    loginCode: 'Nach der Anmeldung fragt die Registrierstelle nach diesem Bestätigungscode:',
    loginWait: 'Lassen Sie diese Seite geöffnet. Sie geht weiter, sobald Sie angemeldet sind.',
    waiting: 'Warten auf Ihre Anmeldung…',
    haveCredential: 'Sie haben Ihre Wahlberechtigung. Ihr Eintrag im öffentlichen Wählerverzeichnis ist {0}.',
    voteTitle: '2. Kandidaten reihen',
    rules: 'Sie können bis zu {0} Ränge vergeben.',
    rulesEqual: ' Mehrere Kandidaten können denselben Rang haben.',
    ranked: 'Ihre Reihung, die beste Wahl zuerst',
    rankedEmpty: 'Noch kein Kandidat gereiht.',
    unranked: 'Nicht gereiht',
    unrankedText: 'Nicht gereihte Kandidaten zählen gemeinsam hinter allen gereihten. Wählen Sie einen Kandidaten, um ihn ans Ende Ihrer Reihung zu setzen.',
    add: '{0} reihen',
    up: '{0} nach oben', down: '{0} nach unten', remove: '{0} aus der Reihung nehmen',
    tie: 'Gleicher Rang wie der Kandidat darüber',
    tooManyRanks: 'Sie haben alle {0} Ränge vergeben.',
    review: 'Stimmzettel prüfen',
    confirmTitle: '3. Stimmzettel bestätigen',
    confirmUnranked: 'Nicht gereiht, zählen hinter allen gereihten: {0}.',
    confirmEmpty: 'Sie reihen keinen Kandidaten. Das ist ein leerer Stimmzettel.',
    confirmText: 'Ein abgegebener Stimmzettel lässt sich nicht ändern.',
    cast: 'Stimmzettel abgeben', change: 'Reihung ändern',
    casting: 'Ihr Stimmzettel wird verschlüsselt und abgegeben…',
    doneTitle: 'Ihr Stimmzettel ist abgegeben',
    doneFull: 'Die Urne hat eine Quittung signiert; sie liegt in diesem Browser. Nach dem Schluss können Sie hier prüfen, ob Ihr Stimmzettel im öffentlichen Log steht.',
    doneNone: 'Diese Wahl gibt keine Quittungen aus. Dieser Browser hat Ihre Berechtigung und Ihren Stimmzettel gelöscht.',
    check: 'Meinen Stimmzettel prüfen',
    checking: 'Das öffentliche Log wird geprüft…',
    notPublished: 'Das Log ist gültig. Die Stimmzettel werden beim Schluss veröffentlicht; prüfen Sie dann erneut.',
    included: 'Ihr Stimmzettel steht im öffentlichen Log.',
    decrypted: 'Er wurde entschlüsselt als: {0}',
    invalid: 'Er ist als ungültig markiert: {0}',
    winners: 'Gewählt: {0}',
    backupTitle: 'Sicherung',
    backupText: 'Speichern Sie Berechtigung, Stimmzettel und Quittung in einer Datei, die mit einer Passphrase verschlüsselt ist, oder laden Sie eine solche Datei, um auf diesem Gerät weiterzumachen.',
    passphrase: 'Passphrase (mindestens 8 Zeichen)',
    export: 'Sicherungsdatei speichern',
    import: 'Sicherungsdatei laden',
    imported: 'Sicherung geladen.',
    badPassphrase: 'Die Passphrase ist zu kurz, oder sie öffnet diese Datei nicht.',
  },
};

const $ = (id) => document.getElementById(id);
let lang = (navigator.language || 'en').startsWith('de') ? 'de' : 'en';
const t = (key, ...args) => args.reduce((s, a, i) => s.replace('{' + i + '}', a), T[lang][key]);

const params = new URLSearchParams(location.search);
const storageKey = 'stimmig:' + params.get('election');
let state = null;   // the client state of the WebAssembly module
let info = null;    // the election
let ranking = [];   // [{id, tied}] in order; tied: same rank as the one before
let lastStatus = ['loading'];

function save() { localStorage.setItem(storageKey, JSON.stringify(state)); }
function setStatus(key, ...args) { lastStatus = [key, ...args]; $('status').textContent = key ? t(key, ...args) : ''; }
function showError(err) {
  $('error').hidden = !err;
  $('error').textContent = err ? String(err.message || err) : '';
}
const call = async (fn, ...args) => JSON.parse(await window[fn](JSON.stringify(state), ...args));
const hex = (b64) => Array.from(atob(b64), (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
const text = (r) => r.map((g) => g.join(' = ')).join(' > ');

function groups() {
  const out = [];
  for (const c of ranking) {
    if (c.tied && out.length) out[out.length - 1].push(c.id); else out.push([c.id]);
  }
  return out;
}
const maxRanks = () => info.tally.max_ranks || info.tally.candidates.length;
const equalRanks = () => !info.tally.no_equal_ranks;

function button(label, onClick, glyph) {
  const b = document.createElement('button');
  b.type = 'button';
  if (glyph) { b.textContent = glyph; b.setAttribute('aria-label', label); b.title = label; } else b.textContent = label;
  b.addEventListener('click', onClick);
  return b;
}

function move(from, to) {
  if (to < 0 || to >= ranking.length) return;
  ranking.splice(to, 0, ...ranking.splice(from, 1));
  ranking[0].tied = false;
  renderRanking(to);
}

// renderRanking draws both lists. focus is the index in the ranking whose
// first control gets the focus, so that keyboard users keep their place.
function renderRanking(focus) {
  if (ranking.length) ranking[0].tied = false;
  // Too many ranks after a change: tie or drop from the end.
  while (groups().length > maxRanks()) {
    if (equalRanks()) ranking[ranking.length - 1].tied = true; else ranking.pop();
  }
  const ol = $('ranked');
  ol.replaceChildren();
  let rank = 0;
  ranking.forEach((c, i) => {
    if (!c.tied) rank++;
    const li = document.createElement('li');
    li.classList.toggle('tied', c.tied);
    li.draggable = true;
    li.addEventListener('dragstart', (e) => e.dataTransfer.setData('text/plain', String(i)));
    li.addEventListener('dragover', (e) => { e.preventDefault(); li.classList.add('over'); });
    li.addEventListener('dragleave', () => li.classList.remove('over'));
    li.addEventListener('drop', (e) => { e.preventDefault(); move(Number(e.dataTransfer.getData('text/plain')), i); });
    const n = document.createElement('span');
    n.className = 'rank';
    n.textContent = rank + '.';
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = c.id;
    li.append(n, name, button(t('up', c.id), () => move(i, i - 1), '↑'), button(t('down', c.id), () => move(i, i + 1), '↓'));
    if (equalRanks() && i > 0) {
      const tie = button(t('tie'), () => { c.tied = !c.tied; renderRanking(i); }, '=');
      tie.setAttribute('aria-pressed', String(c.tied));
      li.append(tie);
    }
    li.append(button(t('remove', c.id), () => { ranking.splice(i, 1); renderRanking(Math.min(i, ranking.length - 1)); }, '×'));
    ol.append(li);
  });
  $('ranked-empty').hidden = ranking.length > 0;
  const ul = $('unranked');
  ul.replaceChildren();
  const full = groups().length >= maxRanks() && !equalRanks();
  for (const id of info.order.filter((id) => !ranking.some((c) => c.id === id))) {
    const li = document.createElement('li');
    const add = button(t('add', id), () => {
      ranking.push({ id, tied: groups().length >= maxRanks() });
      renderRanking(ranking.length - 1);
    });
    add.disabled = full;
    li.append(add);
    ul.append(li);
  }
  if (full) setStatus('tooManyRanks', maxRanks());
  if (focus >= 0 && ol.children[focus]) ol.children[focus].querySelector('button').focus();
}

function render() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll('[data-t]')) el.textContent = t(el.dataset.t);
  $('lang-en').setAttribute('aria-pressed', String(lang === 'en'));
  $('lang-de').setAttribute('aria-pressed', String(lang === 'de'));
  setStatus(...lastStatus);
  if (!info) return;
  $('title').textContent = document.title = info.title;
  $('info').hidden = false;
  $('phase').textContent = t('phase', info.phase, info.eligible, info.issued, info.cast);
  const hasCredential = Boolean(state.credential_signature);
  const hasBallot = Boolean(state.ballot);
  const doneNone = state.cast_without_receipt;
  $('register').hidden = hasCredential || doneNone;
  $('vote').hidden = !hasCredential || hasBallot || !$('confirm').hidden;
  $('done').hidden = !(hasBallot || doneNone);
  $('check').hidden = !hasBallot;
  $('backup').hidden = doneNone;
  $('done-text').textContent = t(doneNone ? 'doneNone' : 'doneFull');
  $('vote-rules').textContent = t('rules', maxRanks()) + (equalRanks() ? t('rulesEqual') : '');
  if (!$('vote').hidden) renderRanking(-1);
}

async function register() {
  showError();
  $('begin').disabled = true;
  try {
    const begun = await call('stimmigBegin');
    state = begun.state;
    save(); // before the login: the credential is issued once and needs this state
    $('login-link').href = begun.login_url;
    $('login-code').textContent = begun.code;
    $('login').hidden = false;
    setStatus('waiting');
    state = (await call('stimmigComplete')).state;
    save();
    $('login').hidden = true;
    info = { ...(await call('stimmigInfo')), order: info.order }; // new counts
    setStatus('haveCredential', hex(state.roll_reference));
  } catch (err) {
    showError(err);
  }
  $('begin').disabled = false;
  render();
}

function review() {
  const ranked = groups();
  const ol = $('confirm-ranking');
  ol.replaceChildren();
  ranked.forEach((g, i) => {
    const li = document.createElement('li');
    li.textContent = (i + 1) + '. ' + g.join(' = ');
    ol.append(li);
  });
  const rest = info.tally.candidates.filter((id) => !ranking.some((c) => c.id === id));
  $('confirm-unranked').textContent = ranked.length === 0 ? t('confirmEmpty') : rest.length ? t('confirmUnranked', rest.join(', ')) : '';
  $('confirm').hidden = false;
  render();
  $('confirm-h').tabIndex = -1;
  $('confirm-h').focus();
}

async function cast() {
  showError();
  setStatus('casting');
  $('cast').disabled = true;
  try {
    const out = await call('stimmigCast', JSON.stringify(groups()));
    const none = !out.error && !out.state.ballot;
    state = out.state;
    if (none) state.cast_without_receipt = true;
    save();
    if (out.error) throw new Error(out.error);
    $('confirm').hidden = true;
    setStatus('');
  } catch (err) {
    setStatus('');
    showError(err);
  }
  $('cast').disabled = false;
  render();
}

async function check() {
  showError();
  setStatus('checking');
  const box = $('check-result');
  box.replaceChildren();
  try {
    const c = await call('stimmigCheck');
    info = { ...(await call('stimmigInfo')), order: info.order }; // new phase and counts
    render();
    const lines = [];
    if (!c.Included) lines.push(t('notPublished'));
    else {
      lines.push(t('included'));
      if (c.Invalid) lines.push(t('invalid', c.Invalid));
      else if (c.Result) lines.push(t('decrypted', text(c.Ranking || [])));
    }
    if (c.Result) lines.push(t('winners', (c.Result.winners || []).join(', ')));
    for (const line of lines) {
      const p = document.createElement('p');
      p.textContent = line;
      box.append(p);
    }
    setStatus('');
  } catch (err) {
    setStatus('');
    showError(err);
  }
}

// The backup file is the state, encrypted with AES-256-GCM under a key
// derived from the passphrase with PBKDF2-SHA256.
async function backupKey(passphrase, salt) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function exportBackup() {
  showError();
  const passphrase = $('passphrase').value;
  if (passphrase.length < 8) return showError(t('badPassphrase'));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await backupKey(passphrase, salt), new TextEncoder().encode(JSON.stringify(state)));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([salt, iv, data]));
  a.download = 'election-' + params.get('election').slice(0, 8) + '.stimmig';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function importBackup(file) {
  showError();
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const key = await backupKey($('passphrase').value, buf.slice(0, 16));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(16, 28) }, key, buf.slice(28));
    const loaded = JSON.parse(new TextDecoder().decode(plain));
    if (loaded.election_id !== state.election_id) throw new Error();
    state = loaded;
    save();
    setStatus('imported');
    render();
  } catch {
    showError(t('badPassphrase'));
  }
}

async function start() {
  for (const l of ['en', 'de']) $('lang-' + l).addEventListener('click', () => { lang = l; render(); });
  $('begin').addEventListener('click', register);
  $('review').addEventListener('click', review);
  $('change').addEventListener('click', () => { $('confirm').hidden = true; render(); });
  $('cast').addEventListener('click', cast);
  $('check').addEventListener('click', check);
  $('export').addEventListener('click', exportBackup);
  $('import-file').addEventListener('change', (e) => e.target.files[0] && importBackup(e.target.files[0]));
  render();
  const id = params.get('election') || '';
  if (!/^[0-9a-f]{64}$/.test(id) || !params.get('log') || !params.get('registrar')) {
    setStatus('');
    return showError(t('missing'));
  }
  state = JSON.parse(localStorage.getItem(storageKey)) || {
    log_url: params.get('log'),
    registrar_url: params.get('registrar'),
    ballot_box_url: location.origin,
    election_id: btoa(String.fromCharCode(...id.match(/../g).map((h) => parseInt(h, 16)))),
  };
  try {
    const go = new Go();
    const wasm = await WebAssembly.instantiateStreaming(fetch('stimmig.wasm'), go.importObject);
    const ready = new Promise((resolve) => addEventListener('stimmig-ready', resolve, { once: true }));
    go.run(wasm.instance);
    await ready;
    info = await call('stimmigInfo');
    // A random order, so that no candidate gains from being listed first.
    info.order = info.tally.candidates.map((id) => [crypto.getRandomValues(new Uint32Array(1))[0], id]).sort((a, b) => a[0] - b[0]).map((p) => p[1]);
    setStatus('');
  } catch (err) {
    setStatus('');
    showError(err);
  }
  render();
}

start();
