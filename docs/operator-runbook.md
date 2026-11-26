# Operator runbook

How to run one election with Stimmig, from preparation to the published
result. It assumes the Docker Compose installation of
[`deploy/compose`](../deploy/compose/README.md); with the Helm chart the steps
are the same and only the commands for logs and backups differ.

The words follow SPEC.md: the **registrar** hands out voting credentials, the
**ballot box** takes the ballots, the **log** is the public record that
anyone can verify.

## What this installation protects, and what it does not

Read this before you promise anything to voters.

- **Ballots are anonymous towards the registrar and the ballot box on their
  own.** The registrar signs credentials blindly, so it cannot link a ballot
  to a voter. That holds as long as the registrar and the ballot box do not
  combine what they know.
- **With Docker Compose, one person runs both.** Whoever controls the host
  can read every ballot before the close, and can try to link ballots to
  voters by the time and the network address of registration and casting.
  That is acceptable for a demo, a club or a team poll. For an election
  that matters, the registrar and the ballot box must be run by different
  parties (SPEC.md section 2), and the protocol should have had an external
  review first.
- **Everyone can check the result.** After the tally, the log holds every
  ballot, its decryption and the result, and anyone can recompute it.
- **A receipt lets a voter prove how they voted.** That makes vote buying
  and coercion easier. Receipt mode `none` (below) gives none, at the cost
  that voters cannot check their own ballot.

## Before the election

### Once per installation

1. Install as described in `deploy/compose/README.md`, with Caddy or behind
   your own reverse proxy.
2. **Back up `.env` now, somewhere other than the host.** It holds the keys
   that open the private keys in the database, the election key among them.
   Without it, an election cannot be tallied, and nothing can recover it.
3. Mail: configure the SMTP server in `.env` and remove `PRINT_MAILS=1`.
   Voters get one mail each, with a login link. To keep it out of spam
   folders, the sender address (`SMTP_FROM`) should belong to a domain whose
   SPF and DKIM records allow your SMTP server.
4. **Run a test election with yourself and one or two others,** on the real
   installation, through to the tally and the check. It is the only way to
   find mail and certificate problems before voters do. Test elections stay
   in the log; give them a title that says so.

### For each election

1. **The voter list.** One voter per line: an email address, or
   `oidc:<issuer>#<subject>` for OpenID Connect login. The list **cannot be
   changed once it is published.** A voter who is missing cannot be added,
   and an address with a typo can never log in. Check the list twice, ideally
   against a second source. Duplicates are counted once.
2. **The definition.** In the admin web page, under "New election", edit the
   JSON template:

   ```json
   {
     "title": "Board election 2027",
     "receipt_mode": "full",
     "tally": {
       "candidates": ["Ada", "Bob", "Cleo"],
       "method": "schulze",
       "max_ranks": 2
     },
     "schedule": {
       "registration_close": "2027-03-01T18:00:00+01:00",
       "voting_open": "2027-03-02T08:00:00+01:00",
       "voting_close": "2027-03-08T18:00:00+01:00"
     }
   }
   ```

   - `candidates`: the names exactly as voters will see them. Up to 500.
   - `method`: `schulze` is the default and the only method that the
     independent verifier in `pyverify` can check. The others are listed in
     SPEC.md section 8; `seats` above 1 needs `schulze` or `stv`.
   - `max_ranks`: how many ranks a voter may use. Leave it out for no limit.
     A small electorate with many possible rankings lets a voter mark their
     ballot with an unusual ranking, which helps vote buying; the admin page
     warns about this when you publish the roll. Lowering `max_ranks` is the
     remedy.
   - `receipt_mode`: `full` (default) gives every voter a receipt to check
     their ballot after the close. `none` gives none and protects better
     against vote buying, but nobody can check their own ballot.
   - `schedule`: optional; the services close and open the phases by
     themselves at these times (they check every 15 seconds). Registration
     must close before voting opens: a gap between them is what keeps the
     time of registration from pointing to a ballot. Without a schedule you
     do each step by hand.
   - Tie-breaking (`tie_break`, `fixed_order`) is described in SPEC.md
     section 8. Without it, a tie is broken by most first ranks and otherwise
     reported as a tie.

   Press **Check** to validate it and see the number of possible ballots,
   then **Create the election**. The page shows the election's ID.

   The definition is fixed from now on: it is the first entry of the public
   log.
3. **Publish the roll:** paste the voter list and publish it. This opens the
   registration. Afterwards delete any copies of the list that you do not
   need. Stimmig does not store the addresses, only salted hashes of them,
   but whoever has the list and the database can tell who registered (not how
   they voted).

## Tell the voters

Send voters, by a channel of your own (not through Stimmig):

- The link: `https://vote.<domain>/?election=<ID>`.
- The dates of registration and voting.
- What will happen, in two steps:
  1. **Get your voting credential** (during registration). The page shows a
     login link and an 8-digit **confirmation code**. The voter enters their
     address, opens the mail they receive, and types the code on the page that
     the link opens. The code is shown only on the voting page; **anyone who
     asks a voter for "their code" in a mail or on the phone is attacking the
     election.**
  2. **Cast the ballot** (during voting), in the same browser.
- **Use the same browser and device for both steps, or make a backup.** The
  credential lives in the browser. A lost credential cannot be issued again.
  The page offers an encrypted backup file.
- After the close, voters can press "Check my ballot" to see that their
  ballot is in the public log and how it was decrypted.

## During the election

Watch the admin web page: it shows, from the verified public log, the phase
and the numbers of eligible voters, issued credentials and cast ballots.

| Phase | What happens | Your step without a schedule |
| --- | --- | --- |
| Registration | Voters get their credentials | **Close the registration** |
| Registration closed | Nothing can change the number of credentials | **Open the voting** |
| Voting open | Voters cast ballots; ballots are not public yet | **Close the voting** |
| Closing | All ballots are published in the log | **Publish the key and the result** |
| Complete | Result and all decryptions are public | Verify (below) |

Each step asks for confirmation and cannot be undone.

### Common problems

- **"I did not get the mail."** Check spam. The registrar sends at most one
  login mail per address per minute. Look at `docker compose logs registrar`
  for mail errors: they show the SMTP step and code, never the address. If
  the address on the list has a typo, that voter cannot vote in this
  election.
- **"The page says a credential was already issued."** The voter registered
  before, maybe in another browser. Only that browser, or a backup file from
  it, holds the credential. It cannot be issued again; this is what keeps
  one person to one vote while the credential stays anonymous.
- **"My ballot was refused."** If the voting is not open yet or has closed,
  the page says so. A ballot that breaks the rules (too many ranks) is
  refused by the page before it is sent.
- **A service is down.** `docker compose ps`, `docker compose logs <service>`,
  `docker compose up -d`. Data is in the database; ballots already accepted
  are kept. If the answer to a cast was lost, the page keeps that ballot: the
  voter casts the same ranking again and gets the receipt, also if the ballot
  box had already stored it. A different ranking is refused until then.
- **A scheduled step did not happen.** Do it by hand in the admin page. A
  failed scheduled close is retried every 15 seconds; the logs say why it
  failed.

Do not update the software while an election runs: a new build changes the
hash of the voting page that the election's definition names.

## After the close

1. **Tally** (by hand, or by the schedule after the voting closes). This
   publishes the election's private key, the decryption of every ballot and
   the result with its full calculation.
2. **Verify** the published log yourself, with both verifiers:

   ```sh
   curl -s https://log.<domain>/v1/elections/<ID>/export -o election.cbor
   docker compose run --rm --no-deps -T log verify /dev/stdin < election.cbor
   python3 pyverify/verify.py election.cbor   # needs: pip install cryptography
   ```

   Both must say OK. `pyverify` checks Schulze elections only.
3. **Publish** the result together with the export file and its SHA-256, so
   that others can verify the same bytes:

   ```sh
   sha256sum election.cbor
   ```

4. **Ask voters to check their ballot** with "Check my ballot". A voter
   whose receipt is valid but whose ballot is missing from the log has proof
   that the ballot box misbehaved.
5. **Disputes.** Set a period in which voters can raise problems before you
   treat the result as final.

## Keeping and deleting data

- The log is public and meant to be kept: it is the evidence of the result.
- The registrar's database links salted hashes of the voters' addresses to
  their issued credentials. It does not link credentials to ballots. Once the
  dispute period is over, you can remove the whole installation with
  `docker compose down -v`; keep the export file.
- Back up during the election: the database
  (`docker compose exec db pg_dumpall -U postgres > backup.sql`) and `.env`.
  A backup of the database is as sensitive as the database: it holds the
  election key until the tally.

## If something goes badly wrong

- **`.env` is lost** before the tally: the election cannot be tallied.
  Announce it, and run it again.
- **You suspect the host was compromised** during the election: the
  published log still shows whether the result is consistent with the
  ballots, and receipts show whether ballots are missing, but secrecy of
  the ballots cannot be restored. Announce it.
- **The verifiers disagree, or one fails:** do not publish the result as
  final. Keep the export file and report it as a bug.
