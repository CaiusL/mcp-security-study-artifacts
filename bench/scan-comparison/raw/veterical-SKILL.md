---
name: veterical
description: Read and manage veterinary-clinic data with the `veterical` CLI — the clients who own the animals, the patients (the animals themselves), appointments, invoices, payments and vaccination records, backed by the Veterical REST API at api.veterical.com. Use when asked to look up, create, update or delete Veterical clients, patients, appointments, invoices, payments or vaccinations, to check a clinic's calendar or client list, to register an animal, or for anything involving the `veterical` command or app.veterical.com data.
license: Apache-2.0
compatibility: Requires Node.js 18+, network access, and a Veterical account — log in through the browser or with an API key (created at https://app.veterical.com)
metadata:
  author: Veterical
  version: '1.0.0'
  repository: https://github.com/veterical/skills
allowed-tools: Bash(veterical:*) Bash(npx veterical:*)
---

# Veterical CLI

`veterical` reads and manages the data on
[app.veterical.com](https://app.veterical.com) through the Veterical REST API:
clients, patients, appointments, invoices, payments and vaccination records —
the same records the clinic dashboard shows.

Two of the nouns are easy to mix up. A **client** is the human who owns the
animal. A **patient** is the animal itself. A patient therefore belongs to a
client, and an appointment usually names both.

Run it as `veterical` when installed globally (`npm install -g veterical`) or
as `npx veterical` otherwise. `veterical --help` and
`veterical <command> --help` are accurate and self-sufficient;
`veterical schema` prints the whole command tree as JSON — prefer those over
memory when unsure of a flag. `veterical skills list` names the guides bundled
with the installed version, and `veterical skills get veterical` prints the
copy of this guide matching it.

## Setup

No account yet? Create one without leaving the terminal — the generated
password prints exactly once, the first clinic is seeded for you, and the
session is stored so every other command works immediately:

```bash
veterical signup --email vet@example.com --json
```

```bash
veterical login                # interactive: browser, another device or API key
veterical login --browser      # opens app.veterical.com/cli; stores a session
veterical login --device       # approve from a phone or another computer; stores a session
veterical login --with-key     # masked prompt for an API key secret
veterical logout               # clears everything stored in ~/.veterical/
```

Three ways in, all stored in `~/.veterical/`:

- **Browser** — `veterical login --browser` opens
  [app.veterical.com](https://app.veterical.com) to sign in and stores a token
  session, refreshed automatically. A browser session is organization-wide, so
  it can reach every clinic of the organization — and must name a clinic on
  writes.
- **Another device** — `veterical login --device` prints a link such as
  `https://app.veterical.com/cli?code=WDJB-MJHT`, a QR code and a one-time code,
  then waits up to ten minutes for someone signed in to Veterical to approve it
  on a phone or computer, and stores the same token session as the browser
  login. It needs neither a browser on this machine nor a terminal: when you run
  it for someone, give them the link and the code.
- **API key** — an administrator of the organization creates a key in the
  dashboard, on the clinic page under **API keys**. The secret is shown once,
  at creation. `veterical login --with-key` prompts for it interactively,
  masked — never pass it as a command argument and never echo it, so it stays
  out of shell history and transcripts. A key belongs to exactly one clinic,
  which is then implied on every call.

Headless agents can skip logging in entirely: export
`VETERICAL_API_KEY=<key secret>` and every command authenticates with it at
request time. When several credentials exist the precedence is: stored browser
session, then stored key, then the environment variable — a stored login always
wins over an exported key.

Without a terminal nothing hangs and no browser is ever opened: `login` exits 1
immediately with instructions on stderr, and commands run with no credentials
fail the same way. A `401` ending in "Not logged in?" means log in again, or
export `VETERICAL_API_KEY`, then retry.

### Scopes

An API key carries per-resource scopes: `clients:read`, `clients:write`,
`patients:read`, `patients:write`, `appointments:read`, `appointments:write`,
`invoices:read`, `invoices:write`, `payments:read`, `payments:write`,
`vaccinations:read`, `vaccinations:write`. New keys start read-only. A `403`
naming a missing scope is a permissions gap, not a bug — an administrator
widens the key in the dashboard. Requests are rate limited per key; a `429`
means back off, not retry-loop. A browser login carries the user's own
permissions instead of key scopes.

Users, roles, invites, clinics, quotes, documents, templates, preferences,
printers and subscriptions are deliberately outside the key vocabulary and
cannot be reached with an API key at all.

## Where to start

| You want                             | Run                                        |
| ------------------------------------ | ------------------------------------------ |
| The owners on file                   | `veterical clients list`                   |
| Find an owner by email               | `veterical clients list --email <email>`   |
| The animals on file                  | `veterical patients list`                  |
| A calendar window                    | `veterical appointments list --startTime … --endTime …` |
| Billing for one animal               | `veterical invoices list --patientId <id>` |
| Recorded payments                    | `veterical payments list`                  |
| Vaccination history and recalls      | `veterical vaccinations list --patientId <id>` |
| One record, formatted                | `veterical clients read <id>` (or the patients / appointments / invoices / payments / vaccinations equivalent) |
| The command tree as JSON             | `veterical schema` (or `veterical schema clients list` for one subtree) |

Ids are Veterical record ids — get them from the `list` commands, never guess
them. A record owned by another clinic or organization responds `404`,
indistinguishable from a missing one; that is tenant isolation, not an error to
work around.

## Clients — the animal owners

```bash
veterical clients list                              # --json for raw output
veterical clients list --clinicId <clinicId>        # one clinic only
veterical clients list --email jane@example.com     # exact-email lookup
veterical clients list --ids <id1,id2>              # fetch specific ids
veterical clients list --fields name,email,phone    # project fields
veterical clients get <clientId>
veterical clients read <clientId>
veterical clients add --name "Jane Fonda" --email jane@example.com \
  --phone 5551234567 --clinicId <clinicId>
veterical clients update <clientId> --phone 5559876543
veterical clients update <clientId> --body '{"language":"it"}'
veterical clients delete <clientId...>              # one or more ids — permanent
```

`--email` on list is an exact match, not a search. `add` is not idempotent —
list first and check the owner does not already exist before creating one.

## Patients — the animals

```bash
veterical patients list                             # --clinicId, --ids, --fields
veterical patients get <patientId>
veterical patients read <patientId>
veterical patients add --name Luna --clientId <clientId> --species dog \
  --breed "Labrador Retriever" --sex female --dateOfBirth 2021-04-18 \
  --clinicId <clinicId>
veterical patients update <patientId> --microchip 981000000000000
veterical patients delete <patientId...>            # one or more ids — permanent
```

Register an animal against the `clientId` of the owner who brought it in; look
that owner up first rather than creating a duplicate.

## Appointments

```bash
veterical appointments list                         # --clinicId, --clientId, --patientId
veterical appointments list --startTime 2026-08-01T00:00:00.000Z \
  --endTime 2026-09-01T00:00:00.000Z                # ISO-8601 window
veterical appointments list --sortField startTime --sortDirection ASC -n 50
veterical appointments get <appointmentId>
veterical appointments read <appointmentId>
veterical appointments add --startTime 2026-08-10T14:00:00.000Z \
  --endTime 2026-08-10T14:30:00.000Z --clientId <clientId> \
  --patientId <patientId> --clinicId <clinicId>
veterical appointments update <appointmentId> --status CANCELED
veterical appointments delete <appointmentId...>    # one or more ids — permanent
```

`--status` accepts `REQUESTED`, `SCHEDULED` (the default), `CLIENT_ARRIVED`,
`NO_SHOW`, `CANCELED`. A visit the owner booked themselves on the clinic's
public site arrives as `REQUESTED` and waits for the clinic to approve it. The
window filter is start-inclusive and end-exclusive. To cancel a visit prefer
`--status CANCELED` over deleting it — deletion is permanent and also cancels
the appointment's scheduled reminders. Booking counts against the clinic's
plan; a rejected create can mean the monthly appointment allowance is used up,
not that the request was malformed.

## Invoices

```bash
veterical invoices list                             # --clinicId, --patientId
veterical invoices list --startTime <iso> --endTime <iso> -n 50 --skip 0
veterical invoices get <invoiceId>
veterical invoices read <invoiceId>
veterical invoices add --patientId <patientId> --status DRAFT --total 120 \
  --clinicId <clinicId>
veterical invoices update <invoiceId> --status PAID
veterical invoices delete <invoiceId...>            # one or more ids — permanent
```

`--status` accepts `DRAFT`, `PENDING`, `PARTIALLY_PAID`, `PAID`, `OVERDUE`,
`REFUNDED`, `UNCOLLECTIBLE`. Amounts are in the clinic currency. Line items
live in the record's own fields — send them through `--body '<json>'`.

## Payments

```bash
veterical payments list                             # --clinicId, --patientId
veterical payments list --startTime <iso> --endTime <iso> --sortField startTime
veterical payments get <paymentId>
veterical payments read <paymentId>
veterical payments add --patientId <patientId> --clinicId <clinicId> \
  --startTime <iso> --note "card terminal"
veterical payments update <paymentId> --note "corrected"
veterical payments delete <paymentId...>            # one or more ids — permanent
```

These are the clinic's own bookkeeping records. Writing one records money that
was already taken — it never charges a card, captures, refunds or moves funds.

## Vaccinations

```bash
veterical vaccinations list                         # --clinicId, --clientId
veterical vaccinations list --patientId <patientId>
veterical vaccinations list --appointmentId <appointmentId>
veterical vaccinations get <vaccinationId>
veterical vaccinations read <vaccinationId>
veterical vaccinations add --patientId <patientId> --clientId <clientId> \
  --vaccine Rabies --administeredDate 2026-07-01 --nextDueDate 2027-07-01 \
  --clinicId <clinicId>
veterical vaccinations update <vaccinationId> --nextDueDate 2027-08-01
veterical vaccinations delete <vaccinationId...>    # one or more ids — permanent
```

Vaccination records drive the clinic's recall reminders: a record carrying a
`reminders` array schedules recall jobs when written, and deleting the record
cancels them. Changing `nextDueDate` reschedules them. Do not use these records
to give medical advice or to decide what an animal should receive — they are
the clinic's log of what a veterinarian already did.

## Writes — the rules that bite

- **Every create and update needs a clinic.** An API key supplies its own
  clinic automatically; a browser session does not, so pass `--clinicId`. On
  `update` without the flag the CLI reads the record first and reuses its
  clinic — that path also needs the matching `:read` scope.
- **`update` sends only the fields you pass**, merged into the stored record.
  Arbitrary fields go through `--body '<json>'`; named options win over
  `--body` on conflict.
- **Writes fire webhooks** (`client.created`, `appointment.updated`,
  `vaccination.created`, …) to the clinic's subscribed endpoints, exactly like
  dashboard edits — a bulk import loop triggers one delivery per record.
- **Deletes are permanent** and variadic. Confirm with the user and resolve
  names to ids via `list` before deleting anything.
- These are real medical and personal records for real animals and their
  owners. Read before you write, never invent a value to satisfy a required
  flag, and never paste record contents anywhere the user did not ask for.

## Output discipline

Every subcommand accepts `--json`: real, parseable `JSON.stringify` output on
stdout — no colors, no `util.inspect`. Without the flag, `list` and `read`
print terminal summaries. Mutations with `--json` print a small result object —
`{ "ok": true, "id": "…" }` for `add`/`update`,
`{ "ok": true, "deleted": ["…"] }` for `delete`.

Failures always go to stderr with exit code 1; with `--json` the error is a
single JSON line, `{"error":{"message":"…","status":404}}`, so stdout stays
parseable.

When exploring, project instead of dumping — use `--fields` server-side or pipe
`--json` through `jq` and keep only what you need:

```bash
veterical clients list --json --fields _id,name,email | jq '.[] | {id: ._id, name}'
```

## Schema

```bash
veterical schema                # the whole command tree as JSON
veterical schema clients list   # one subtree: its options and arguments
```

Every command, option, and positional argument as parseable JSON — use it to
discover capabilities instead of scraping `--help` text.

## Skills

```bash
veterical skills list             # bundled agent guides
veterical skills get veterical    # this guide, matching the installed version
```

## Configuration

`VETERICAL_API_URL` overrides the API endpoint (default
`https://api.veterical.com`) — only for non-production deployments.
`VETERICAL_API_KEY` supplies an API key secret from the environment for
headless use — no login step needed, but a stored login outranks it. Stored
credentials live only in `~/.veterical/`.

## Errors → remediation

| Symptom                                 | Fix                                                   |
| --------------------------------------- | ----------------------------------------------------- |
| `401` / "Not logged in?"                | `veterical login`, or export `VETERICAL_API_KEY`, then retry |
| `403: Invalid api key`                  | The stored secret is wrong — `veterical login --with-key` again |
| `403` naming a missing scope            | Widen the key's scopes in the Veterical dashboard     |
| `404` on an id you were given           | Wrong id, or the record belongs to another clinic     |
| `400: missing clinicId`                 | Pass `--clinicId` (see Writes above)                  |
| `429`                                   | Per-key rate limit — wait, do not retry-loop          |
| An owner appears twice                  | `add` is not idempotent — list by `--email` first     |
