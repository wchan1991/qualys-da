# Qualys Data Analytics -- Plain-English Formula Guide

**Audience:** Anyone who looks at the dashboards and wants to know what the
numbers actually mean. No code, no SQL -- just everyday English and a few
pictures drawn with keyboard characters.

**How to use this document:** Each metric follows the same four-part template:

1. **Where you see it** -- which page or card on the dashboard.
2. **What it is** -- one-sentence plain definition.
3. **How it works** -- the recipe, in words anyone can follow.
4. **What does this tell me?** -- why you should care.

---

## Quick Analogy Cheat-Sheet

Before we dive in, here are the analogies used throughout this guide:

- **Vulnerabilities** = holes in a fence. Each hole is a way something
  bad could get through. Some holes are tiny (severity 1), some are
  gaping (severity 5).
- **TruRisk score** = a reverse health score for a computer. Zero is
  perfectly healthy; the higher the number, the sicker the machine.
- **SLA (Service-Level Agreement)** = a homework deadline. Each
  severity level gets its own deadline, and you either turn it in on
  time or you don't.
- **Waterfall / bathtub model** = a bathtub with the tap running and
  the drain open. New vulnerabilities are water pouring in; fixes are
  water draining out. The water level is your active vulnerability
  count.
- **Coverage** = smoke detectors in a building. If every room has one,
  you have 100% coverage. Rooms without a detector are blind spots.
- **Reopen rate** = fixing a door that keeps swinging open. You thought
  you fixed it, but it popped open again.

---

## ASCII Diagrams

Five reference pictures you can come back to any time.

### 1. Severity Pyramid

The most dangerous vulnerabilities are the rarest (we hope), sitting at
the top of the pyramid. The wider the layer, the more vulnerabilities
of that type you have.

```
                   /\
                  /  \
                 / 5  \        Sev 5 -- Urgent / Critical
                /------\
               /   4    \      Sev 4 -- High
              /----------\
             /     3      \    Sev 3 -- Medium
            /--------------\
           /       2        \  Sev 2 -- Low
          /------------------\
         /        1           \ Sev 1 -- Minimal / Info
        /______________________\

  Fewer vulns at the top = good.
  A fat top layer = alarm bells.
```

### 2. Coverage Venn Diagram

Two overlapping circles show where your asset-inventory system (CSAM)
and your vulnerability scanner (VM) agree and disagree about which
devices exist.

```
       .--------.          .--------.
      /  CSAM    \        /   VM     \
     |  only      |      |   only     |
     |   (no scan |      |  (no asset |
     |    data)   |      |   record)  |
      \     .----+---------+----.    /
       \   /     |  BOTH  |     \  /
        `-|      | (full  |      |'
          |      | picture|      |
           \     |________|     /
            `------------------'

  "Both" = smoke detectors installed AND working.
  CSAM-only or VM-only = blind spots.
```

### 3. Waterfall (Bathtub) Flow

Each month, vulnerabilities flow in (new), flow out (fixed), and
sometimes flow back in (reopened). The water level at the end is your
active count.

```
  Active
  Count
    |
    |  START                                          END
    |  =====                                          ===
    |  |   |   +New   -Fixed  +Reopen  +New   -Fixed  |   |
    |  |   |   |///|                    |///|          |   |
    |  |   |   |///|  |   |   |\\\\|   |///|  |   |   |   |
    |  |   |   |///|  |---|   |\\\\|   |///|  |---|   |   |
    |  |___|   |///|  |   |   |\\\\|   |///|  |   |   |___|
    |          |///|  |   |   |\\\\|   |///|  |   |
    +----------+---+--+---+---+----+---+---+--+---+---------
               Jan    Feb      Mar      Apr    May

  /// = water pouring in (new + reopened)
  --- = water draining out (fixed)
  Net each month = New - Fixed + Reopened
```

### 4. SLA Timeline

Every vulnerability gets a stopwatch that starts when it is first
discovered. The allowed time depends on severity.

```
  Discovery                                    Deadline
     |                                            |
     v                                            v
     *--------------------------------------------X
     |<---------- SLA window (days) ------------>|

     Severity 5 (Urgent):  |====|  7 days
     Severity 4 (High):    |==========|  30 days
     Severity 3 (Medium):  |====================|  90 days
     Severity 2 (Low):     |==============================|  180 days
     Severity 1 (Minimal): |==========================================| 365 days

  If you fix it before X  -->  Compliant  (homework turned in on time)
  If it is still open at X --> Breaching  (late homework)
```

### 5. Change Detection -- Before / After

The system takes two snapshots of every vulnerability and compares them
like two class photos taken a week apart.

```
  SNAPSHOT A (last pull)          SNAPSHOT B (new pull)
  -----------------------         -----------------------
  Host1:QID100  Active     --->   Host1:QID100  Active      (no change)
  Host1:QID200  Active     --->   Host1:QID200  Fixed       ==> "fixed"
  Host2:QID300  Fixed      --->   Host2:QID300  Active      ==> "reopened"
  Host3:QID400  Active     --->       (gone)                ==> "fixed" *
                                  Host4:QID500  New         ==> "new"

  * If a vulnerability disappears from the API entirely, the system
    treats it as fixed (the scanner no longer sees the hole).
```

---
---

# Main Dashboard

---

## Dashboard Overview (`dashboard_summary`)

**Where you see it:** The main landing page when you open the app.

**What it is:** A single bundle that contains everything the home page
needs -- vulnerability totals, KPI badges, asset coverage, risk
distribution, and the timestamp of the last data refresh.

**How it works:** The system calls five other metrics (described below)
and packages their results together into one delivery. It does not do
any math of its own -- think of it as the waiter who brings every dish
to the table at once.

**What does this tell me?** Nothing by itself -- it is a container. But
it guarantees the home page shows a consistent set of numbers that were
all calculated from the same data snapshot.

---

## Vulnerability Overview (`vuln_overview`)

**Where you see it:** The top cards on the main dashboard showing total
vulnerabilities, counts by severity, and counts by status.

**What it is:** The grand total of every vulnerability the scanner
knows about, sliced two ways: by severity (how dangerous) and by status
(what stage of its life cycle).

**How it works:**

1. Look at the most recent data pull (the "latest snapshot").
2. Count every non-disabled vulnerability, grouped by severity level
   (1 through 5).
3. Count again, this time grouped by status (New, Active, Fixed,
   Re-Opened).
4. Add up all the severity counts to get the grand total.
5. "Critical count" = severity 5 + severity 4 combined (the top two
   tiers of the pyramid).
6. Separately count how many vulnerabilities are disabled (excluded
   from all other metrics).

**What does this tell me?** This is your big-picture snapshot. If the
total is going up, more holes are appearing in the fence than you are
patching. If critical count is high, you have large holes that need
urgent attention.

---

## KPI Badges (`kpi_badges`)

**Where you see it:** Five small badges on the main dashboard -- quick
health-check numbers you can read at a glance.

**What it is:** Five headline numbers pulled from deeper metrics:

1. **Patchable %** -- how many open vulnerabilities have a known fix.
2. **Avg MTTR** -- average days to fix a vulnerability.
3. **SLA Compliance %** -- percentage of vulnerabilities fixed within
   their deadline.
4. **Scan Coverage %** -- percentage of all known devices scanned in
   the last 30 days.
5. **Reopen Rate** -- percentage of "fixed" vulnerabilities that came
   back.

**How it works:** Each badge is simply the headline number from a
deeper metric (patchable_percentage, detection_age, sla_compliance,
asset_coverage, and reopen_rate respectively). No extra math -- just
picking the most important number from each report.

**What does this tell me?** Think of these as the vital signs on a
hospital monitor. Green = healthy. If any badge turns red, click into
the full KPI page to find out why.

---

## Risk Distribution (`risk_distribution`)

**Where you see it:** The histograms and "Top 10 Riskiest Hosts" table
on the main dashboard.

**What it is:** Two bar charts showing how risk is spread across your
environment, plus a list of the ten most troubled machines.

**How it works:**

- **TruRisk histogram:** Take every host (computer) with a TruRisk
  score above zero. Drop each score into a bucket of 100 (0-99,
  100-199, 200-299, and so on). Count how many hosts land in each
  bucket. This tells you whether most machines are low-risk or whether
  you have a long tail of high-risk machines.

- **QDS histogram (detection-level):** Same idea, but for individual
  vulnerability detection scores, using buckets of 20 (0-19, 20-39,
  etc.). Only non-disabled detections with a QDS above zero are
  counted.

- **Top 10 riskiest hosts:** Sort all hosts by TruRisk score from
  highest to lowest. Take the first ten. These are the machines that
  need the most attention.

**What does this tell me?** If the histogram is bunched on the left
(low scores), your environment is generally healthy. If there is a
long bump on the right, you have pockets of serious risk. The top-10
list tells you exactly which machines to look at first.

---

## Asset & Scan Coverage (`asset_coverage` / `scan_coverage`)

**Where you see it:** The Venn-diagram coverage card on the main
dashboard and the KPI page.

**What it is:** A measure of how many of your known devices are
actually being scanned for vulnerabilities. Think of it as counting
how many rooms in the building have working smoke detectors.

**How it works:**

1. Collect every unique IP address from the asset inventory (CSAM).
2. Collect every unique IP address from the vulnerability scanner (VM).
3. Find the overlap -- IPs that appear in BOTH lists. These are your
   "fully covered" devices.
4. Find IPs only in CSAM (known device, never scanned -- blind spot).
5. Find IPs only in VM (scanned, but not in the official inventory --
   rogue or unregistered device).
6. **Coverage %** = devices in both lists / total unique devices x 100.
7. **Scanned in 7 days** = how many devices had a scan within the past
   week.
8. **Scanned in 30 days** = how many devices had a scan within the past
   month.
9. **Scan coverage 7d/30d %** = scanned count / total unique devices
   x 100.

`scan_coverage` is simply another name for `asset_coverage` -- they
return the same numbers.

**What does this tell me?** Low coverage means parts of your network
are invisible. You cannot fix holes you cannot see. Aim for as close
to 100% as possible, and investigate any CSAM-only or VM-only devices.

---

## Detection Age & MTTR (`detection_age`)

**Where you see it:** The MTTR badge on the dashboard and the aging
buckets on the KPI page.

**What it is:** Two things in one: how fast you fix vulnerabilities on
average, and how many old unfixed vulnerabilities are still hanging
around.

**How it works:**

- **MTTR (Mean Time to Remediate):** For every vulnerability whose
  status is "Fixed", calculate the number of days between when it was
  first discovered and when it was last fixed. Average all those day
  counts together. That average is your MTTR.

- **Aging buckets (30/60/90 day):** For every open (New or Active)
  non-disabled vulnerability, check how old it is. Count how many are
  older than 30 days, how many are older than 60 days, and how many
  are older than 90 days. (A vulnerability older than 90 days also
  counts in the 60-day and 30-day buckets.)

**What does this tell me?** MTTR tells you your average repair speed.
The aging buckets show how much backlog is piling up. If the 90-day
bucket is growing, your team is falling behind on old issues.

---

## OS Distribution (`os_distribution`)

**Where you see it:** The "Vulnerabilities by Operating System" chart
on the main dashboard.

**What it is:** A breakdown showing which operating systems carry the
most vulnerabilities and how dense the problems are.

**How it works:**

1. Join the host list (which has the OS name) with the detection list
   (which has the vulnerabilities).
2. For each OS, count the number of distinct hosts and the number of
   open, non-disabled vulnerabilities.
3. **Density** = vulnerability count / host count. This is "vulns per
   host" and tells you whether an OS has a few heavily-loaded machines
   or many lightly-loaded ones.
4. Return the top 20 operating systems sorted by vulnerability count.

**What does this tell me?** If one OS has a very high density, it may
need targeted patching or hardening. An OS with many hosts but low
density is in better shape than one with few hosts but sky-high
density.

---

## Application Distribution (`app_distribution`)

**Where you see it:** The "Vulnerabilities by Application" chart on the
main dashboard.

**What it is:** Similar to OS distribution, but for installed
applications. It uses the software inventory from the asset management
system (CSAM) to see which apps are associated with the most
vulnerabilities.

**How it works:**

1. From the asset inventory, read the software list for every device.
2. Build a map: application name --> which IP addresses have it
   installed.
3. From the vulnerability scanner, count open vulnerabilities per IP.
4. For each application, add up the vulnerabilities across all the IPs
   where it is installed.
5. **Density** = total vulns for that app / number of hosts with it.
6. Return the top 30 applications sorted by vulnerability count.

**What does this tell me?** If a particular version of Java or Apache
is driving a huge chunk of your vulnerability count, you know where to
focus your patching effort. High density means "every machine running
this app is heavily affected."

---

## Top Vulnerability Types (`top_qids`)

**Where you see it:** The "Most Common Vulnerabilities" table on the
main dashboard.

**What it is:** A ranked list of the most frequently occurring
vulnerability types (identified by their QID -- Qualys ID) across your
environment.

**How it works:**

1. Look at all open, non-disabled detections in the latest snapshot.
2. Group them by QID (vulnerability type).
3. For each QID, count the total number of occurrences and the number
   of distinct hosts affected.
4. Sort by total count, highest first.
5. Return the top 20 (by default).

**What does this tell me?** These are your most widespread problems. A
QID that appears on hundreds of hosts is a prime target for a single
patching campaign -- one fix, many hosts improved.

---
---

# Operational KPIs

---

## Full KPI Report Card (`all_kpis`)

**Where you see it:** The dedicated KPI page.

**What it is:** A wrapper that bundles every operational metric into one
view: patchable percentage, MTTR by severity, SLA compliance, scan
coverage, detection fix rate, reopen rate, detection age, and the
vulnerability overview.

**How it works:** It calls each of the metrics listed below and
packages them together. No additional math.

**What does this tell me?** This is your complete report card. If you
can only look at one page, this is the one.

---

## Patchable Percentage (`patchable_percentage`)

**Where you see it:** The "Patchable %" badge on the dashboard and the
KPI page.

**What it is:** Of all your open vulnerabilities, what percentage have
a known, available patch? In other words, how many holes in the fence
could you fix right now if you had the time?

**How it works:**

1. Look at all open (New/Active), non-disabled vulnerabilities.
2. Check each one's detection type: "Confirmed" means a patch exists;
   "Potential" means there may not be a straightforward fix.
3. **Patchable %** = Confirmed count / total open count x 100.

**What does this tell me?** A high patchable percentage is actually
good news -- it means most of your problems have a known solution. A
low percentage means many issues require workarounds, configuration
changes, or waiting for a vendor patch.

---

## Patchable by Severity (`patchable_by_severity`)

**Where you see it:** The patchable breakdown chart on the KPI page.

**What it is:** The same patchable-vs-not-patchable split, but broken
down for each severity level so you can see whether your critical
vulnerabilities are fixable.

**How it works:**

1. Look at all open (New/Active/Re-Opened), non-disabled detections.
2. For each severity level (1 through 5), count how many have the
   "patchable" flag set and how many do not.
3. Per severity: **Patchable %** = patchable count / (patchable +
   non-patchable) x 100.
4. Overall: **Total patchable %** = sum of all patchable / sum of all
   (patchable + non-patchable) x 100.

**What does this tell me?** If severity-5 patchable percentage is low,
your most dangerous vulnerabilities are the hardest to fix -- that is a
red flag. If it is high, you have patches waiting to be deployed and
should prioritize getting them installed.

---

## MTTR by Severity (`mttr_by_severity`)

**Where you see it:** The MTTR breakdown table on the KPI page.

**What it is:** The average number of days it takes to fix a
vulnerability, broken down by how severe the vulnerability is.

**How it works:**

1. Look at all Fixed detections that have both a "first found" and a
   "last fixed" date.
2. For each one, calculate: days to fix = last fixed date minus first
   found date.
3. Group by severity and average the days within each group.
4. Round to one decimal place.

**What does this tell me?** You would expect severity-5 vulnerabilities
to be fixed fastest (shortest deadline). If severity-5 MTTR is higher
than severity-3, something is wrong with your prioritization. Compare
these numbers to your SLA deadlines to see if you are meeting your own
targets on average.

---

## SLA Compliance (`sla_compliance`)

**Where you see it:** The SLA Compliance badge and the SLA breakdown
table on the KPI page.

**What it is:** The percentage of open vulnerabilities that are still
within their allowed fix-time window (the homework deadline). Each
severity gets a different deadline:

| Severity | Default Deadline |
|----------|-----------------|
| 5 (Urgent) | 7 days |
| 4 (High) | 30 days |
| 3 (Medium) | 90 days |
| 2 (Low) | 180 days |
| 1 (Minimal) | 365 days |

(These defaults can be changed by an administrator.)

**How it works:**

1. For each severity level, count how many open (New/Active),
   non-disabled vulnerabilities exist.
2. Of those, count how many have been open longer than the allowed
   deadline ("breaching").
3. **Compliant** = total open minus breaching.
4. **Compliance % (per severity)** = compliant / total open x 100.
5. **Overall compliance %** = sum of all compliant across all
   severities / sum of all open across all severities x 100.

Important: the overall percentage is weighted by the number of open
vulnerabilities, not a simple average of the five per-severity
percentages. A severity with 1,000 open vulns counts more than one
with 10.

**What does this tell me?** If SLA compliance is 95%, then 95 out of
every 100 vulnerabilities are being handled within their deadline. If
it drops, your team is falling behind. Focus on the severity level
with the lowest compliance first.

---

## Detection Fix Rate (`detection_fix_rate`)

**Where you see it:** The KPI page, showing how the balance between
new and fixed vulnerabilities shifted in the last 7 days.

**What it is:** A comparison of how many new vulnerabilities appeared
versus how many were fixed in the past week. This comes from the
change log, not from the current state of vulnerabilities.

**How it works:**

1. Look at the change log for the last 7 days.
2. Count entries marked "new" (vulnerabilities that appeared).
3. Count entries marked "fixed" (vulnerabilities that were resolved).
4. **Net change** = new count minus fixed count. Positive means the
   backlog grew; negative means it shrank.
5. **Fix ratio** = fixed count / new count x 100.

**What does this tell me?** A fix ratio above 100% means you are
fixing vulnerabilities faster than they appear -- the bathtub is
draining. Below 100% means the water level is rising. This is one of
the most important operational health indicators.

---

## Reopen Rate (`reopen_rate`)

**Where you see it:** The "Reopen Rate" badge on the dashboard and KPI
page.

**What it is:** Of all the vulnerabilities that were once marked
"Fixed" or "Re-Opened", what percentage bounced back to Re-Opened?
This is the door that keeps swinging open after you fix it.

**How it works:**

1. Look at all non-disabled detections in the latest snapshot.
2. Count how many have status "Re-Opened".
3. Count how many have status "Fixed" OR "Re-Opened" (the total pool
   of things that were fixed at some point).
4. **Reopen rate %** = re-opened count / (fixed + re-opened) x 100.

**What does this tell me?** A high reopen rate means your fixes are
not sticking. Possible causes: incomplete patches, configuration
drift, or machines being rebuilt from unpatched images. Investigate
the specific vulnerabilities that keep coming back.

---
---

# CVE Dashboard

---

## CVE Overview (`cve_dashboard`)

**Where you see it:** The dedicated CVE (Common Vulnerabilities and
Exposures) page.

**What it is:** A focused view of vulnerabilities organized by their
industry-standard CVE identifier and scored using CVSS (Common
Vulnerability Scoring System) instead of the Qualys severity scale.

CVSS bands:

| Band | CVSS Score Range |
|----------|-----------------|
| Critical | 9.0 and above |
| High | 7.0 to 8.9 |
| Medium | 4.0 to 6.9 |
| Low | above 0, below 4.0 |

**How it works:**

1. Look at all open (New/Active/Re-Opened), non-disabled detections.
2. Band each detection by its CVSS base score using the table above.
3. Count distinct CVE IDs, distinct IP addresses (resources), and
   totals per CVSS band.
4. **Coverage %** = resources scanned / total unique IPs (from asset
   coverage) x 100.
5. **12-month trend:** For each of the past 12 months, count
   detections whose "first found" date falls in that month, banded by
   CVSS.
6. **Top resources:** The 10 hosts with the most open vulnerabilities.
7. **Top patchable CVEs:** The 10 CVEs that have a known fix and
   affect the most hosts.
8. **Top CVEs overall:** The 10 most widespread CVEs by host count.

Important: This page counts OPEN detections only. The main dashboard's
vuln_overview counts ALL non-disabled detections including Fixed. So
the CVE dashboard total will always be equal to or smaller than the
main dashboard total.

**What does this tell me?** This page helps you speak the same language
as public vulnerability advisories. When a news article says
"CVE-2024-XXXXX is critical," you can come here and see exactly how
many of your hosts are affected and whether a patch exists.

---

## CVE by Ownership (`cve_by_ownership`)

**Where you see it:** The ownership breakdown table on the CVE page.

**What it is:** The same CVSS banding as the CVE overview, but split
by whoever is responsible for each group of devices -- by owner,
business unit, tag, or OS.

**How it works:**

1. Map each IP address to its group (owner, business unit, tag, or
   OS).
2. For each group, count open detections per CVSS band, distinct CVE
   IDs, unique hosts, highest CVSS score, and the single most
   prevalent CVE.
3. **Enterprise totals** are calculated with a single query across ALL
   detections, not by adding up the group numbers. This prevents
   double-counting when a device belongs to multiple groups (common
   with tags).

**What does this tell me?** It answers "which team or department has
the most critical CVE exposure?" and lets managers compare groups
fairly. The enterprise row gives the true organization-wide number.

---
---

# Cyber 6-Pack

---

## 6-Pack Scorecard (`cyber_six_pack`)

**Where you see it:** The Cyber 6-Pack page -- a per-group report card.

**What it is:** For each ownership group, a set of four key numbers:
weighted average age of open vulnerabilities, count of SLA-breaching
vulnerabilities, total open vulnerability count, and SLA compliance
percentage.

**How it works (per group):**

1. **Weighted average age:** For each open vulnerability in the group,
   calculate its age in days (today minus first-found date). Multiply
   each age by the number of vulnerabilities at that age, add them all
   up, then divide by the total vulnerability count. This gives more
   weight to large clusters of old vulnerabilities.

2. **SLA breaching:** Count how many open vulnerabilities have been
   open longer than their severity's SLA deadline.

3. **Total vulns:** Count of all open, non-disabled vulnerabilities
   for the group.

4. **SLA compliance %** = (total vulns - SLA breaching) / total vulns
   x 100.

**Enterprise row (the "whole company" line):**

- Enterprise weighted avg age = sum of (each group's avg age x its
  vuln count) / sum of all groups' vuln counts. (Weighted by size, so
  a big group counts more.)
- Enterprise SLA compliance = (sum of all total vulns - sum of all
  breaching) / sum of all total vulns x 100.

**What does this tell me?** This is the executive summary. At a
glance, you can see which groups are managing their vulnerabilities
well and which are falling behind. A high average age combined with
low SLA compliance is a red flag that needs management attention.

---

## 6-Pack Trend (`cyber_six_pack_trend`)

**Where you see it:** The trend charts on the Cyber 6-Pack page,
showing 12 months of history for the top 8 groups.

**What it is:** A month-by-month view of how average vulnerability age
and SLA breaches have changed over time for each group.

**How it works:**

1. Take the current snapshot of open vulnerabilities.
2. Bucket each vulnerability by the month it was first discovered.
3. For each group and each monthly bucket, calculate:
   - **avg_age** = average number of days from first-found to today
     for vulnerabilities in that bucket.
   - **sla_breaches** = count of vulnerabilities in that bucket whose
     age exceeds their severity's SLA window.
4. Chart the top 8 groups (by size) across 12 months.

**Caveat -- directional, not exact:** This uses today's snapshot to
look backward. A vulnerability that was fixed three months ago will
not appear in the data because it is no longer in the current
snapshot. So the trend is directional (shows the right shape) but not
a perfect historical record.

**What does this tell me?** Rising average age means old
vulnerabilities are accumulating. Rising SLA breaches means deadlines
are being missed more frequently. Both trending down is the goal.

---

## Waterfall by Ownership (`waterfall_by_ownership`)

**Where you see it:** The waterfall (bathtub) chart on the Cyber
6-Pack page.

**What it is:** A month-by-month accounting of how the active
vulnerability count changed: how many flowed in (new), how many
drained out (fixed), and how many flowed back in (reopened).

**How it works:**

Picture a bathtub:

1. **End active** = current count of open (New/Active/Re-Opened),
   non-disabled vulnerabilities. This is the water level right now.
2. For each of the past 12 months, look at the change log and count:
   - **New:** vulnerabilities that appeared for the first time.
   - **Fixed:** vulnerabilities that were resolved.
   - **Reopened:** vulnerabilities that came back after being fixed.
3. **Net (per month)** = new - fixed + reopened.
   - Positive net = water level rose (more holes opened than closed).
   - Negative net = water level fell (you are winning).
4. **Start active** is calculated backward: take the current active
   count and subtract all the monthly net changes. This gives the
   estimated active count at the beginning of the 12-month window.
5. **Running total** = start active, then add each month's net in
   order. The last running total should equal end active.
6. **Reconciled** = a true/false check that confirms the running total
   lines up with the current active count. If false, it means some
   changes fell outside the 12-month window.

When scoped to a specific owner or group, the counts are filtered to
only include devices belonging to that group.

**What does this tell me?** This is the most powerful trend chart. If
the bathtub is filling (running total going up), you need either more
patching capacity or fewer new vulnerabilities. If it is draining, you
are making progress. The new/fixed/reopened breakdown tells you
exactly where the water is coming from and going to.

---
---

# Tags & Grouping

---

## Tag Summary (`tag_summary`)

**Where you see it:** The tag overview table.

**What it is:** A summary row for every tag (label) applied to your
hosts, showing how many hosts have that tag, how many vulnerabilities
those hosts carry, average severity, and average TruRisk.

**How it works:**

1. Look at the latest host-tag assignments.
2. For each tag, count distinct IP addresses (host count).
3. Join with vulnerability data to get total vuln count per tag.
4. Sort by vulnerability count, highest first.

**What does this tell me?** Tags often represent locations, business
functions, or environments (e.g., "Production", "DMZ", "Finance").
This table shows which tagged groups carry the most risk.

---

## Tag Detail (`tag_detail`)

**Where you see it:** The detail view when you click on a specific tag.

**What it is:** A full breakdown for one tag: the list of hosts in
that tag, plus a vulnerability summary split by severity and status.

**How it works:**

1. Retrieve up to 500 hosts that carry the selected tag.
2. For those hosts, count vulnerabilities grouped by severity AND
   status.
3. Aggregate into totals: total count, by-severity counts, by-status
   counts.

**What does this tell me?** This is your deep-dive into one tag. It
answers "for my Production servers, how many critical vulns are open
vs. fixed?"

---

## Tag Comparison (`tag_comparison`)

**Where you see it:** The side-by-side comparison view on the tags
page.

**What it is:** Tag detail called for multiple tags at once, so you
can compare them next to each other.

**How it works:** Calls tag_detail for each tag in the list and
returns them side by side.

**What does this tell me?** It answers "Is Production in better shape
than Staging?" or "How does the New York office compare to London?"

---

## Monitored Tag Dashboard (`monitored_tag_dashboard`)

**Where you see it:** The watched-tags dashboard widget (if
configured).

**What it is:** A tag comparison for tags that an administrator has
marked as "monitored" (important to watch).

**How it works:** Reads the list of monitored tags from configuration,
then calls tag_comparison with that list. Returns an empty list if no
tags have been configured for monitoring.

**What does this tell me?** This is the shortcut for tags your
organization cares most about. Instead of manually comparing tags each
time, the admin sets them up once and they appear automatically.

---
---

# Ownership & Responsibility

---

## Ownership Summary (`ownership_summary`)

**Where you see it:** The ownership overview table.

**What it is:** A per-owner breakdown showing total open
vulnerabilities, critical count, and average severity for each owner.

**How it works:**

1. Load all ownership rules (which map IP addresses to owners).
2. For each owner, find all their IPs.
3. Count open (New/Active), non-disabled vulnerabilities on those IPs.
4. Count how many are severity 4 or 5 (critical).
5. **Average severity** = sum of all severity values / total vuln
   count.
6. Sort by total vulnerabilities, highest first.

**What does this tell me?** It answers "who owns the most risk?" and
helps management allocate remediation resources to the teams that need
them most.

---

## OS by Ownership (`os_by_ownership`)

**Where you see it:** The stacked bar chart showing vulnerabilities
per OS per ownership group.

**What it is:** A matrix where rows are ownership groups and columns
are OS families (Windows, Linux, macOS, Other). Each cell shows how
many open vulnerabilities fall in that combination.

**How it works:**

1. Classify every host's OS into a family:
   - Contains "windows" --> Windows
   - Contains "linux", "ubuntu", "red hat", "centos", etc. --> Linux
   - Contains "mac" or "darwin" --> macOS
   - Everything else --> Other
2. Map each IP to its ownership group.
3. Count open, non-disabled vulnerabilities per IP.
4. For each (group, OS-family) pair, add up the vulnerability counts.
5. Return the top 15 groups for chart readability.

**What does this tell me?** It answers "Is the Finance team's problem
mostly Windows or Linux?" so remediation efforts can target the right
platform for the right team.

---

## Orphaned Assets (`orphaned_assets`)

**Where you see it:** The Orphaned Assets page.

**What it is:** A list of devices that do not match any ownership rule
-- they belong to nobody. These are the abandoned houses on the street
that nobody is maintaining.

**How it works:**

1. Combine all IPs from both the asset inventory (CSAM) and the
   vulnerability scanner (VM).
2. For each IP, check whether any ownership rule claims it.
3. If no rule matches, the device is "orphaned."
4. For each orphan, gather: which sources it appears in (CSAM, VM, or
   both), its OS, last scan date, TruRisk score, open vulnerability
   count, and any tags.
5. Sort by open vulnerability count (most vulns first), then by
   TruRisk score.

**What does this tell me?** Orphaned assets are a governance gap.
Nobody is responsible for patching them, so vulnerabilities can pile
up unchecked. This list helps you assign owners or decommission
devices that should not exist.

---
---

# Trends & History

---

## Weekly Trends (`weekly_trends`)

**Where you see it:** The weekly trend charts on the Trends page.

**What it is:** A 12-week history of all major metrics: total vulns,
per-severity counts, per-status counts, new and fixed this week,
average TruRisk, coverage, and aging.

**How it works:** Reads directly from the weekly rollup table. Each
row in that table is a weekly snapshot built by compute_weekly_rollup
(described below). The trend display simply reads the most recent 12
rows.

**What does this tell me?** Trends over weeks show whether your
vulnerability posture is improving or deteriorating. A rising total
vulns line is bad; a falling one is good.

---

## Monthly Trends (`monthly_trends`)

**Where you see it:** The monthly trend charts on the Trends page.

**What it is:** Same shape as weekly trends, but with 12 months of
history instead of 12 weeks.

**How it works:** Reads directly from the monthly rollup table.

**What does this tell me?** Monthly trends smooth out the week-to-week
noise and show the longer arc. This is the view executives care about.

---

## Week over Week (`week_over_week`)

**Where you see it:** The "Changes this week" summary on the Trends
page.

**What it is:** A simple comparison between this week's numbers and
last week's numbers for key metrics.

**How it works:**

1. Read the two most recent weekly rollup rows.
2. For each key metric (total vulns, severity-5 count, severity-4
   count, new, active, fixed, average TruRisk, total hosts), compute:
   **delta** = this week's value minus last week's value.
3. Return this week, last week, and the deltas.

**What does this tell me?** It answers "did things get better or worse
since last week?" A positive delta on total vulns means the backlog
grew. A negative delta means it shrank.

---

## Recent Changes (`recent_changes`)

**Where you see it:** The "Last 7 Days" activity card.

**What it is:** A count of how many vulnerabilities were newly
discovered, fixed, reopened, or had a severity change in the past 7
days.

**How it works:**

1. Look at the change log for the past 7 days.
2. Group by change type (new, fixed, reopened, severity_change).
3. Count each group.

**What does this tell me?** This is your week-at-a-glance activity
summary. High "new" with low "fixed" means you are falling behind.
A high "reopened" count means fixes are not holding. A high
"severity_change" count means the risk landscape is shifting.

---

## How Weekly Rollups Are Built (`compute_weekly_rollup`)

**Where you see it:** You don't see this directly -- it runs in the
background every week to create the data that weekly_trends reads.

**What it is:** The process that takes a snapshot of all live data and
compresses it into a single summary row for the week.

**How it works:**

1. Run vuln_overview to get total vulns, per-severity counts, and
   per-status counts.
2. Count new and fixed detections this week from the change log.
3. Calculate average and maximum TruRisk scores from the host table.
4. Calculate average QDS (detection score) from the detection table.
5. Run asset_coverage to get host counts and coverage percentages.
6. Run detection_age to get the 30/60/90-day aging bucket counts.
7. For each monitored tag, compute host count, vuln count, and
   by-severity breakdown.
8. Package everything into one row keyed to the Monday of this week
   and save it.

**What does this tell me?** This is the engine behind your trend
charts. Without it, you would only ever see the current state with no
history.

---

## How Monthly Rollups Are Built (`compute_monthly_rollup`)

**Where you see it:** Same as above -- runs in the background to feed
monthly trend data.

**What it is:** A simplified version of the weekly rollup that creates
monthly history.

**How it works:**

1. Take the most recent weekly rollup row.
2. Change the date label from "week starting Monday" to "month
   starting the 1st."
3. Rename "new this week" to "new this month" (and same for "fixed").
4. Save as a monthly rollup row.

Note: it does NOT re-aggregate from raw data. It simply relabels the
latest weekly snapshot. This means the monthly number reflects the
state at the time of the last weekly rollup, not a full-month
recalculation.

**What does this tell me?** This gives you the long-term view (months
and years) without the computational cost of re-processing every
detection for each historical month.

---
---

# Behind the Scenes

---

## Change Detection (`detect_changes`)

**Where you see it:** You don't see this directly -- it runs
automatically every time new data is pulled from Qualys.

**What it is:** The process that compares two consecutive data pulls
(snapshots) to figure out what changed. Think of it as comparing two
class photos to see who is new, who left, and who moved seats.

**How it works:**

Each vulnerability is identified by a unique key: "host ID + QID"
(which computer + which vulnerability type). The system compares the
old snapshot to the new one:

- **Key not in old snapshot:** This vulnerability is brand new.
  Record it as "new."
- **Key in both, old status was "Fixed", new status is Active/New/
  Re-Opened:** The vulnerability came back. Record it as "reopened."
- **Key in both, old status was NOT "Fixed", new status IS "Fixed":**
  The vulnerability was resolved. Record it as "fixed."
- **Key in both, status changed but is not a fixed/reopen
  transition:** The status shifted (e.g., New to Active). Record it
  as "status_change."
- **Key in old but NOT in new, and old status was not "Fixed":** The
  vulnerability disappeared from the scanner results entirely. The
  system treats this as a fix (the hole is no longer visible).

All these change records are saved to a log. Every trend metric,
rollup, and waterfall chart reads from this log.

**What does this tell me?** This is the foundation of all your
historical data. Without change detection, the system would only know
the current state and could never tell you how things have changed
over time.

---

## Snapshot Retention (`purge_snapshots`)

**Where you see it:** You don't see this directly -- it runs
automatically to keep the database from growing forever.

**What it is:** A grandfather-father-son (GFS) retention policy that
decides which old snapshots to keep and which to delete.

**How it works:**

- **Daily snapshots:** Kept for 30 days, then deleted. This gives you
  day-by-day detail for the recent past.
- **Weekly rollups:** Kept for 52 weeks (one year), then deleted. This
  gives you week-by-week trends for a full year.
- **Monthly rollups:** Kept forever. This gives you long-term history
  stretching back as far as the system has been running.

Think of it like photo albums: you keep every daily selfie for a
month, then keep one photo per week for a year, then keep one photo
per month forever.

**What does this tell me?** You do not need to worry about the
database growing without limit. Old detailed data is automatically
cleaned up while preserving enough history for meaningful trend
analysis.

---

## Cache Refresh (`invalidate_cache`)

**Where you see it:** You don't see this directly -- it happens
automatically after every data refresh.

**What it is:** A reset switch that tells the dashboard to throw away
its saved answers and recalculate everything from fresh data.

**How it works:**

The system keeps a "generation counter" -- a simple number that goes
up by one every time new data arrives. When you load the dashboard, it
checks: "Is my saved answer from the current generation?" If yes, it
serves the saved answer instantly (fast). If no (because a refresh
happened), it recalculates everything from the new data.

This means:
- Between refreshes, the dashboard loads almost instantly because it
  reuses cached results.
- After a refresh, the very next page load takes a moment longer
  because it is computing fresh numbers.
- No stale data is ever shown -- the generation counter guarantees
  the cache is always in sync with the latest pull.

**What does this tell me?** The numbers you see on the dashboard are
always up to date as of the last data pull. You never need to
manually clear a cache or worry about seeing yesterday's data after a
refresh has run.

---
---

# Glossary

| Term | Definition |
|------|-----------|
| **Active** | A vulnerability status meaning the scanner has confirmed this issue still exists on the host. |
| **Aging bucket** | A count of open vulnerabilities older than a threshold (30, 60, or 90 days). |
| **CSAM** | CyberSecurity Asset Management -- the inventory system that knows which devices exist. |
| **CVE** | Common Vulnerabilities and Exposures -- a public, industry-standard ID for a specific vulnerability (e.g., CVE-2024-12345). |
| **CVSS** | Common Vulnerability Scoring System -- a 0-to-10 severity score maintained by the industry, separate from the Qualys severity scale. |
| **Confirmed** | A detection type meaning the vulnerability has been verified and a patch is available. |
| **Coverage** | The percentage of known devices that are being actively scanned. Like smoke detectors per room. |
| **Density** | Vulnerabilities per host. A host with 50 vulns has higher density than one with 5. |
| **Detection** | A single instance of a vulnerability found on a specific host. One CVE on 10 hosts = 10 detections. |
| **Disabled** | A detection that has been manually excluded from metrics (e.g., accepted risk). |
| **fetched_at** | The timestamp of when data was pulled from the Qualys API. The "latest snapshot" is the most recent fetched_at. |
| **Fixed** | A vulnerability status meaning the issue has been resolved (the hole in the fence is patched). |
| **GFS** | Grandfather-Father-Son -- a retention strategy keeping daily, weekly, and monthly snapshots at different lifespans. |
| **Host** | A single computer, server, or device identified by its IP address. |
| **KPI** | Key Performance Indicator -- a number that measures how well you are doing at a specific goal. |
| **MTTR** | Mean Time to Remediate -- the average number of days between discovering a vulnerability and fixing it. |
| **Net change** | New vulnerabilities minus fixed vulnerabilities (plus reopened). Positive = backlog growing. |
| **New** | A vulnerability status meaning it was just discovered for the first time. |
| **Open** | A vulnerability that is not yet fixed. Statuses "New" and "Active" are considered open (some metrics also include "Re-Opened"). |
| **Orphaned asset** | A device that exists in the inventory or scanner but has no assigned owner. |
| **Patchable** | A vulnerability for which a vendor-provided fix (patch) exists and can be applied. |
| **Potential** | A detection type meaning the vulnerability might exist but has not been fully confirmed or may lack a patch. |
| **QDS** | Qualys Detection Score -- a per-detection risk score (0-100) factoring in exploitability and threat intelligence. |
| **QID** | Qualys ID -- a unique identifier for a type of vulnerability in the Qualys knowledge base. |
| **Re-Opened** | A vulnerability status meaning it was previously Fixed but has reappeared. The door swung open again. |
| **Reconciled** | A true/false check on the waterfall chart confirming the math adds up correctly. |
| **Rollup** | A summary snapshot saved at a regular interval (weekly or monthly) for trend analysis. |
| **Severity** | A 1-to-5 scale rating how dangerous a vulnerability is: 1 = minimal, 5 = urgent/critical. |
| **SLA** | Service-Level Agreement -- the maximum allowed time to fix a vulnerability at a given severity. Like a homework deadline. |
| **Snapshot** | A complete copy of all vulnerability data pulled at a specific point in time. |
| **Tag** | A label applied to hosts for grouping (e.g., "Production", "DMZ", "Finance"). |
| **TruRisk** | A Qualys-calculated risk score for a host. Higher = more risk. Think of it as a reverse health score. |
| **VM** | Vulnerability Management -- the scanning system that finds vulnerabilities on devices. |
| **Waterfall** | A chart showing how the active vulnerability count changes month over month (the bathtub model). |
| **Weighted average** | An average where larger groups count more than smaller groups, proportional to their size. |
