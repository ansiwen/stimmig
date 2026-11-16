// Browser check of the voting client against running services. Run it with
// web/check/run.sh, which starts the services. It needs Node.js and the
// playwright package with a Chromium.
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');

const dir = process.env.CHECK_DIR;
const B = process.env.STIMMIG_BIN;
const LOG = 'http://127.0.0.1:18081', REG = 'http://127.0.0.1:18082', BOX = 'http://127.0.0.1:18083';
const env = {
  ...process.env,
  STIMMIG_LOG_URL: LOG, STIMMIG_REGISTRAR_URL: REG, STIMMIG_BALLOTBOX_URL: BOX,
  STIMMIG_LOG_ADMIN_TOKEN: 'log-admin-token-0123456789', STIMMIG_REGISTRAR_ADMIN_TOKEN: 'registrar-admin-token-0123456', STIMMIG_BALLOTBOX_ADMIN_TOKEN: 'ballotbox-admin-token-0123456',
};
const admin = (...args) => execFileSync(B, ['admin', ...args], { env }).toString().trim();
const assert = (cond, msg) => { if (!cond) throw new Error('FAILED: ' + msg); console.log('ok: ' + msg); };

(async () => {
  fs.writeFileSync(dir + '/def.json', JSON.stringify({ title: 'Browser test', tally: { candidates: ['Ada', 'Bob', 'Cleo'], method: 'schulze', max_ranks: 2 } }));
  fs.writeFileSync(dir + '/voters.txt', 'ada@example.org\n');
  const id = admin('create', '-definition', dir + '/def.json');
  admin('roll', '-election', id, '-voters', dir + '/voters.txt');

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 420, height: 900 } });
  const problems = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/40[49]|425/.test(m.text())) problems.push(m.text()); });
  page.on('response', (r) => { if (r.status() >= 400) console.log('http', r.status(), r.url().slice(0, 70)); });
  page.on('pageerror', (e) => problems.push(String(e)));
  // A link may not change where the page registers: it names another
  // registrar, and the page must ignore that.
  const url = `${BOX}/?election=${id}&registrar=${encodeURIComponent('http://evil.example')}&log=${encodeURIComponent('http://evil.example')}`;
  await page.goto(url);
  await page.waitForSelector('#register:not([hidden])', { timeout: 60000 });
  assert((await page.title()) === 'Browser test', 'the page shows the election title');
  const unknown = await browser.newPage();
  await unknown.goto(`${BOX}/?election=${'00'.repeat(32)}`);
  await unknown.waitForSelector('#error:not([hidden])', { timeout: 60000 });
  assert((await unknown.textContent('#error')).includes('does not know'), 'an unknown election is refused');
  await unknown.close();
  assert((await page.textContent('#phase')).includes('Eligible: 1'), 'the page shows the public counts');

  // Register: the page waits while the voter logs in in another tab.
  await page.click('#begin');
  await page.waitForSelector('#login:not([hidden])');
  const loginURL = await page.getAttribute('#login-link', 'href');
  const stored = await page.evaluate((id) => JSON.parse(localStorage.getItem('stimmig:' + id)), id);
  assert(stored.registrar_url === REG && stored.log_url === LOG, 'registrar and log come from the ballot box, not from the link');

  const state = new URL(loginURL).searchParams.get('state');
  const before = fs.readFileSync(dir + '/reg.err', 'utf8').length;
  await fetch(loginURL, { method: 'POST', body: new URLSearchParams({ state, address: 'ada@example.org' }) });
  const mail = fs.readFileSync(dir + '/reg.err', 'utf8').slice(before);
  const link = mail.match(/http:\/\/\S+callback\S+/)[0];

  // Open the link and type the confirmation code that the page shows.
  const typeCode = async (link, code) => {
    const form = await (await fetch(link)).text();
    const token = form.match(/name="token" value="([^"]+)"/)[1];
    return (await fetch(REG + '/v1/confirm', { method: 'POST', body: new URLSearchParams({ token, code }) })).status;
  };
  const code1 = await page.textContent('#login-code');
  assert(/^\d{4} \d{4}$/.test(code1), 'the page shows a confirmation code');
  assert((await typeCode(link, '0000 0000')) === 403, 'a wrong confirmation code is refused');
  assert((await typeCode(link, code1)) === 200, 'the login link and the code issue the credential');
  // Reload before the page has fetched the credential: the registration
  // resumes with the same session and fetches the credential at once.
  await page.reload();
  await page.waitForSelector('#register:not([hidden])', { timeout: 60000 });
  await page.click('#begin');
  assert((await page.textContent('#login-code')) === code1, 'a reload continues the same session and code');
  await page.waitForSelector('#vote:not([hidden])', { timeout: 30000 });
  assert(true, 'the registration resumed after a reload');

  admin('close-registration', '-election', id);

  // A cast before the voting opens is refused, and it is not a cast ballot:
  // the page offers the ranking again, and the next cast sends the new ranking.
  await page.getByRole('button', { name: 'Rank Ada' }).click();
  await page.getByRole('button', { name: 'Rank Bob' }).click();
  await page.click('#review');
  await page.click('#cast');
  await page.waitForSelector('#error:not([hidden])');
  await page.reload();
  await page.waitForSelector('#vote:not([hidden])', { timeout: 60000 });
  assert(await page.isHidden('#done'), 'a refused cast is not shown as cast');
  admin('open-voting', '-election', id);

  // Rank with the buttons and the keyboard.
  await page.click('text=Deutsch');
  assert((await page.textContent('#vote-h')).includes('Kandidaten'), 'the language switches to German');
  await page.click('#lang-en');
  await page.getByRole('button', { name: 'Rank Bob' }).click();
  await page.getByRole('button', { name: 'Rank Ada' }).click();
  await page.getByRole('button', { name: 'Rank Cleo' }).click(); // third candidate, only two ranks: tied with Ada
  let ranked = await page.$$eval('#ranked li', (lis) => lis.map((li) => li.querySelector('.rank').textContent + li.querySelector('.name').textContent));
  assert(JSON.stringify(ranked) === '["1.Bob","2.Ada","2.Cleo"]', 'the rank limit ties the third candidate: ' + ranked);
  await page.getByRole('button', { name: 'Remove Cleo from the ranking' }).click();
  await page.getByRole('button', { name: 'Move Ada up' }).focus();
  await page.keyboard.press('Enter');
  ranked = await page.$$eval('#ranked li', (lis) => lis.map((li) => li.querySelector('.name').textContent));
  assert(JSON.stringify(ranked) === '["Ada","Bob"]', 'the keyboard moves a candidate: ' + ranked);
  const focused = await page.evaluate(() => document.activeElement.getAttribute('aria-label'));
  assert(focused === 'Move Ada up', 'the focus stays with the moved candidate: ' + focused);
  // Drag Bob above Ada.
  await page.dragAndDrop('#ranked li:nth-child(2)', '#ranked li:nth-child(1)');
  ranked = await page.$$eval('#ranked li', (lis) => lis.map((li) => li.querySelector('.name').textContent));
  assert(JSON.stringify(ranked) === '["Bob","Ada"]', 'drag and drop reorders: ' + ranked);

  await page.click('#review');
  await page.waitForSelector('#confirm:not([hidden])');
  const confirm = await page.textContent('#confirm');
  assert(confirm.includes('1. Bob') && confirm.includes('2. Ada') && confirm.includes('Cleo'), 'the confirmation shows the ballot and the unranked candidate');
  await page.screenshot({ path: dir + '/confirm.png', fullPage: true });
  await page.click('#cast');
  await page.waitForSelector('#done:not([hidden])', { timeout: 30000 });
  assert(true, 'the ballot is cast and the receipt verified');

  // Backup: save the encrypted file, lose the browser storage, load the file.
  await page.fill('#passphrase', 'short');
  await page.click('#export');
  assert((await page.textContent('#error')).includes('too short'), 'a short passphrase is refused');
  await page.fill('#passphrase', 'correct horse battery');
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#export')]);
  await download.saveAs(dir + '/backup.stimmig');
  const backup = fs.readFileSync(dir + '/backup.stimmig');
  assert(backup.length > 500 && !backup.includes('credential_key'), 'the backup file is encrypted');
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await page.waitForSelector('#register:not([hidden])', { timeout: 60000 });
  await page.fill('#passphrase', 'wrong passphrase');
  await page.setInputFiles('#import-file', dir + '/backup.stimmig');
  await page.waitForSelector('#error:not([hidden])');
  assert(await page.isHidden('#done'), 'a wrong passphrase does not open the backup');
  await page.fill('#passphrase', 'correct horse battery');
  await page.setInputFiles('#import-file', []);
  await page.setInputFiles('#import-file', dir + '/backup.stimmig');
  await page.waitForSelector('#done:not([hidden])');
  assert(true, 'the backup restores credential, ballot and receipt');
  // Loading a backup over a credential asks first.
  let asked = '';
  page.once('dialog', async (d) => { asked = d.message(); await d.dismiss(); });
  await page.setInputFiles('#import-file', []);
  await page.setInputFiles('#import-file', dir + '/backup.stimmig');
  await page.waitForTimeout(500);
  assert(asked.includes('already holds'), 'a backup does not silently replace what the browser holds');

  await page.click('#check');
  await page.waitForSelector('#check-result p', { timeout: 30000 }); // not waitForFunction: the page's content security policy forbids the eval it needs
  assert((await page.textContent('#check-result')).includes('published at the close'), 'before the close the ballot is not public');

  admin('close-voting', '-election', id);
  admin('tally', '-election', id);
  await page.reload();
  await page.waitForSelector('#done:not([hidden])', { timeout: 60000 });
  await page.click('#check');
  await page.waitForSelector('#check-result p:has-text("decrypted")', { timeout: 30000 });
  const result = await page.textContent('#check-result');
  assert(result.includes('Bob > Ada') && result.includes('Winners: Bob'), 'after the tally the page shows the decrypted ballot and the result');
  await page.screenshot({ path: dir + '/done.png', fullPage: true });

  // The admin page: sign in, see the election, create another, publish its roll.
  const adm = await browser.newPage();
  adm.on('pageerror', (e) => problems.push(String(e)));
  adm.on('console', (m) => { if (m.type() === 'error' && !/40[19]/.test(m.text())) problems.push(m.text()); });
  await adm.goto('http://127.0.0.1:18090/');
  await adm.fill('#token', 'wrong');
  await adm.click('#signin');
  await adm.waitForSelector('#error:not([hidden])');
  assert((await adm.textContent('#error')).includes('token'), 'the admin page refuses a wrong token');
  await adm.fill('#token', 'admin-web-token-0123');
  await adm.click('#signin');
  await adm.waitForSelector('#elections tr');
  assert((await adm.textContent('#elections')).includes('Browser test'), 'the admin page lists the elections: ' + JSON.stringify(await adm.textContent('#elections')));
  await adm.click('#elections tr');
  await adm.waitForSelector('#winners:has-text("Winners: Bob")');
  assert((await adm.textContent('#facts')).includes('complete'), 'the admin page shows the state of a finished election');
  await adm.click('#create');
  await adm.waitForSelector('#status:has-text("Election created")');
  await adm.fill('#voters', 'ada@example.org\nbob@example.org\n');
  await adm.click('#roll');
  await adm.waitForSelector('#status:has-text("The roll is published")');
  assert((await adm.textContent('#facts')).includes('Eligible / issued / cast2 / 0 / 0') || (await adm.textContent('#facts')).includes('2 / 0 / 0'), 'the admin page publishes a roll');

  assert(problems.length === 0, 'no console errors or content security policy violations: ' + problems.join(' | '));
  await browser.close();
})().catch((e) => { console.error(e.message); process.exit(1); });
