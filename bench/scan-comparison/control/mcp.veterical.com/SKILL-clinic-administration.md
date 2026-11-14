---
name: clinic-administration
description: Review a Veterical clinic's safe administrative configuration and capacity — clinic metadata, bookable capacity summaries, provider display names, aggregate schedules, non-text calendar blocks, numeric catalog data, payment aggregates and plan entitlements. Use when asked about a vet clinic's free appointment slots, how busy each day is, closures and blocked time, bookable staff, catalog prices, payment totals or plan limits through the Veterical connector. Never use for animal or owner records, individual appointments, clinical information, payment execution, medical advice, diagnosis, triage, prescribing or treatment decisions.
license: Apache-2.0
compatibility: Requires the Veterical MCP connector (https://mcp.veterical.com/mcp) and a Veterical account authorized for the intended organization
metadata:
  author: Veterical
  version: '1.0.2'
  repository: https://github.com/veterical/skills
---

# Clinic administration with Veterical

This skill drives the hosted Veterical MCP connector. The user must connect
Veterical and authorize an account that can access the intended organization.
If authorization fails, ask the user to connect or reauthorize; never guess an
identifier or retry with a different tenant.

## Hard privacy, financial and clinical boundary

This connector is administrative-only. It intentionally does not expose:

- animal/patient or owner/client identities, records, contact details or
  record counts;
- individual appointment records, identifiers, statuses, animal/owner links
  or exact booked times;
- diagnoses, treatments, procedure names/descriptions, prescriptions,
  vaccinations, reminders, images or notes;
- provider identifiers, contacts, roles, credentials or organization
  internals;
- transaction identifiers/dates, animal or owner linkage, line items,
  discounts, payment methods, card/bank information or processor identifiers;
  or
- tools that create, update, book, message, cancel, charge, refund, transfer or
  delete anything.

Never ask the user to paste excluded personal or clinical data into chat,
infer it from aggregate counts, or imply that another tool can approximate a
missing capability. The connector does not diagnose, triage, prescribe,
recommend treatment, determine urgency or make any medical decision. It cannot
move funds.

Bookable availability is unassigned clinic capacity inside the clinic's own
online-booking window. Numeric catalog data is administrative configuration,
not evidence that an animal received or should receive a treatment. Patient
and appointment numbers in subscription results are plan caps, not record
counts.

## Available tools

| Tool                          | Use it when someone asks…                                                     |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `list_clinics`                | which clinics they manage; also resolves the clinic ID every other tool needs |
| `get_clinic`                  | about one clinic's currency, language or timezone                             |
| `get_clinic_availability`     | when there are free online-booking slots (up to 14 days with openings)        |
| `list_clinic_providers`       | which vets, nurses or assistants can be booked (up to 100 display names)      |
| `get_clinic_schedule_summary` | how busy each UTC day is (appointment counts, at most 31 days)                |
| `list_calendar_events`        | when the clinic is closed or time is blocked (holidays, vacations, meetings)  |
| `list_procedures`             | about the catalog's price range (rows carry no treatment names)               |
| `list_payments`               | how much was taken in, by currency and payment status, one page at a time     |
| `list_subscriptions`          | which plan the clinic is on and its plan caps                                 |
| `show_clinic_overview`        | for a one-card overview of one clinic                                         |

Every tool is read-only. There is no operation for animal/owner lookup,
individual appointment access, booking, rescheduling, cancellation, messaging,
clinical-record access, diagnosis, treatment, payment execution or funds
movement.

## Identifiers and cursors

Never guess a clinic ID. Start with `list_clinics`, choose the clinic matching
the user's request and reuse its returned 24-character lowercase hexadecimal
ID. If several clinics match, ask which one they mean. A cross-organization ID
fails closed.

Tools returning `nextCursor` use opaque cursors. Reuse a cursor only with the
same clinic, date range and limit that produced it. Start a new listing when a
filter changes. Never inspect, edit or manufacture a cursor.

Counts marked `+` are lower bounds from bounded reads. Do not describe them as
complete totals. Payment groups summarize one bounded page; follow the cursor
only if the user needs subsequent pages, and do not combine pages without
clearly stating what was added.

## Administrative overview workflow

When the user wants a broad snapshot:

1. Call `list_clinics`.
2. Resolve the intended clinic without guessing.
3. Call `show_clinic_overview` with that clinic ID.
4. Interpret only safe clinic metadata, aggregate next-seven-day schedule,
   provider/availability counts and numeric catalog previews.

The card does not identify an appointment, owner, animal, provider record or
procedure label. Never infer one.

## Schedule and capacity workflow

For workload over a period:

1. Resolve the clinic with `list_clinics`.
2. Call `get_clinic_schedule_summary` with ISO 8601 start/end values. Omit
   both for the default seven-day range. Never request more than 31 days.
3. Report only the aggregate count and UTC day rows. Counts include canceled
   appointments; say so when describing workload.
4. Use `get_clinic_availability` separately for open capacity and
   `list_clinic_providers` for display names.

Schedule summaries deliberately omit individual records and times. Do not try
to reconstruct them by comparing availability, provider or calendar output.

## Calendar and numeric catalog workflow

Use `list_calendar_events` for closures, meetings, courses, days off and other
non-appointment blocks. It exposes time, all-day state, scope, effect and type.
Titles, notes, IDs and staff references are unavailable. Do not infer a reason
or person from a block.

Use `list_procedures` for numeric price/duration/edit-time configuration at a
resolved clinic. Names and descriptions are intentionally absent. Never label
a row, map it to an animal, or describe it as a diagnosis, treatment history
or care recommendation.

## Payment aggregates and entitlements

Use `list_payments` only for operational amount/count totals grouped by
currency and status. State that totals cover the bounded page reported by the
tool. Never claim access to a transaction, payment method, processor account
or settlement, and never imply that Claude can authorize, capture, refund or
transfer money.

Use `list_subscriptions` for plan status, billing frequency and configuration
caps. It contains no billed amount or processor customer/subscription record.
Do not interpret patient or appointment caps as actual record counts.

## Unsupported requests

For an animal, owner, individual-appointment or clinical request, state that
the public connector cannot access the requested data. For a write request,
state that every tool is read-only. For payment execution or processor data,
state that only aggregate operational totals are available. For diagnosis,
urgency, medication or treatment advice, do not invoke Veterical as a clinical
authority; follow current host safety guidance and make clear that the
connector provides no medical decision.

## Clinic sidebar

Use `open_veterical` when the user asks to open Veterical or browse their clinics. Select an owned clinic for aggregate schedules, booking capacity and numeric catalog prices and durations. The selection supplies clinic context to the assistant. Every view is read-only and excludes animal, owner and clinical records. Counts marked “At least” are lower bounds.
