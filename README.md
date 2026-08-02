# Rearc Cybersecurity Detection Quest - Submission

## Finding

**Microsoft Word (`WINWORD.EXE`) resolved `www.mediafire.com`.**

Word has no legitimate reason to resolve a consumer file-sharing host. Read
against the surrounding events - every other Word DNS query in the same session
went to Microsoft telemetry infrastructure - this is consistent with macro or
embedded-object execution inside a delivered document reaching out to stage a
second-stage payload.

MITRE: **T1566.001** (Spearphishing Attachment) → **T1105** (Ingress Tool Transfer).

---

## Approach

**Loading.** The Cribl envelope promotes a handful of fields to the top level
(`Computer`, `EventCode`, `User`, `Description`, `host`, `source`, `_time`) and
leaves the full Sysmon event as a string in `_raw`.

**Parsing.** Cribl can ship Windows event data as nested JSON, XML, or
key=value depending on pipeline configuration, and the parse strategy differs
for each. I inspected `_raw` before writing any parsing logic and confirmed it
is flat JSON. I then parsed it with an explicit schema rather than relying on
inference - inference samples the data to guess types, which means the parse can
silently change shape if the input changes, and a detection pipeline should
behave identically on every run.

**Profiling before filtering.** I profiled the `EventCode` distribution before
writing any rule. The dataset is dominated by file deletes (EventCode 23) and
process access (EventCode 10); DNS queries (EventCode 22) are a small fraction.
That subset was small enough to review manually, which I did - the detection is
deliberately simple because the reasoning, not query complexity, is what proves
the hypothesis.

---

## Detection logic

Two conditions:

1. The querying process is an Office application.
2. The queried domain is not Microsoft telemetry.

### Two deliberate design choices

**Basename comparison, not path-tail matching.** I split the image path on the
separator and compare the final element against an explicit set. A naive
`endswith("winword.exe")` would also match a file named `notwinword.exe` - a
trivially easy rule to evade.

**Suffix allowlist, not an enumerated hostname list.** Every legitimate Office
query in this data resolved under `office.com` or `office.net` - update checks,
template CDN, telemetry endpoints. Microsoft adds and retires CDN hostnames
frequently, so a list of specific hosts goes stale and starts producing false
positives without anyone noticing. A suffix rule survives that churn with no
ongoing maintenance.

The trade-off I am accepting: an attacker controlling a subdomain under an
allowlisted suffix would be suppressed. Low likelihood, high impact - mitigation
noted in limitations.

---

## Observations outside the stated hypothesis

Two further artifacts I would raise in a real triage:

- **`C:\Temp\OfficeSetup.exe`** made a DNS query several minutes before the Word
  activity. A genuine Office installer does not run from `C:\Temp` - this is a
  binary masquerading as Microsoft tooling.
- **`<unknown process>`** made a query shortly after. Sysmon could not resolve
  the image name, which typically means the process had already exited by the
  time the event was written - consistent with a short-lived dropper or injected
  thread.

All activity sits on a single host inside a nine-minute window. That temporal
and host clustering is itself corroborating signal.

---

## Normalization

Mapped to **OCSF DNS Activity, `class_uid` 4003**.

A DNS event from Sysmon, from a firewall, and from a resolver all describe the
same real-world thing but name their fields differently. Downstream consumers -
correlation rules, dashboards, the analyst reading the alert - should not need
to know which sensor produced the record. Normalising is what makes that
possible.

I chose OCSF over ECS mainly for its explicit DNS Activity class and its
process / device / actor structure, which maps cleanly onto what Sysmon provides.

---

## Alert packaging

Field selection was driven by one question: *what does an analyst need before
they open the raw event?*

- **Identity and verdict** - rule name, severity, status
- **Where to go** - host, user, process, timestamp
- **What to look for next** - MITRE technique
- **Pivot handles** - `ProcessGuid` is stable across Sysmon event types, so it
  links this DNS event to process creation, file writes, and network connections
  from the same process
- **A readable one-liner** - triageable from a dashboard tile without clicking
  through

**On `alert_id`:** a deterministic SHA-256 over host + process GUID + domain +
timestamp, not a random UUID. Any scheduled detection with lag tolerance will
re-run over overlapping windows; a random id produces duplicate alerts in the
queue, a deterministic one makes deduplication trivial.

The alert is written out to a table at `output/alerts`. Parquet is used so the
notebook stays self-contained; in a real deployment this would be a Delta or
Iceberg table that the SOC queue reads from, appended to rather than
overwritten, and partitioned by detection date.

---

## Enrichment

Enriched against **URLhaus (abuse.ch)**, chosen over VirusTotal or OTX because
it requires no API key - a reviewer can run the notebook without credential
setup, and there is no key to accidentally commit. The call is wrapped so the
notebook executes end to end without network access.

**The interpretation matters more than the lookup.**

`www.mediafire.com` is a legitimate file-sharing service. Every reputation feed
correctly returns *not malicious*. A detection that depended on a
threat-intelligence verdict would have missed this entirely.

The signal is **categorical, not reputational**. The finding is not "this domain
is known-bad" - it is "a document editor has no business resolving a
file-sharing host." Adversaries stage payloads on legitimate services precisely
because those services pass reputation checks.

In production I would enrich with three things rather than one:

- **Category** - file host, paste site, dynamic DNS, URL shortener
- **Prevalence** - first-seen-in-environment is frequently a stronger signal
  than any external verdict
- **Popularity rank** - position against Tranco or Umbrella top-1M

Reputation feeds are a fourth input, not the answer.

---

## Limitations and next steps

- **Primary false negative.** If the macro spawns a separate process
  (`powershell.exe`, `rundll32.exe`, `mshta.exe`) and that process performs the
  DNS query, `Image` is no longer an Office binary and this rule will not fire.
  The fix is to join to EventCode 1 (process create, present in this dataset)
  and evaluate parent-process ancestry rather than the querying image alone.
  **This is the change I would prioritise.**
- **Allowlist scope.** A subdomain under an allowlisted suffix would be
  suppressed. Mitigate by also validating the resolved address against
  Microsoft's published IP ranges, so domain and destination must agree.
- **Allowlist location.** Inline in the notebook for readability. In production
  it belongs in a versioned reference table so tuning does not require a code
  change.
- **No baselining.** With a longer collection window I would score on per-host
  domain rarity rather than applying a static allowlist.
- **False positive rate.** Zero on this dataset, but the DNS subset is far too
  small to characterise one honestly. I would backtest over historical data and
  run in shadow mode before enabling this in production.

---

## Portability

The notebook includes the equivalent detection expressed as **Spark SQL** and as
**SPL**, since Sysmon-via-Cribl commonly lands in Splunk. The SPL is included to
show the rule ports cleanly to the platform where it would most likely run; it
has not been executed against a live Splunk instance.

**pandas equivalents** are included as comments beside each PySpark cell. The
dataset is small enough that single-node pandas would handle it comfortably, and
the comments show the logic is not tied to Spark. The one place Spark is
genuinely better suited is OCSF normalization, where the struct type gives real
schema enforcement that pandas cannot match without serialising to JSON.

---

## Running this notebook

The repository ships a `requirements.txt` and a devcontainer configuration.

```
pip install -r requirements.txt
```

Java 17 or later is required.

I developed this in Google Colab rather than the provided devcontainer, for
convenience. One Colab-specific note worth recording: the preinstalled
`dataproc-spark-connect` package patches `SparkSession.builder` into Spark
Connect mode and prevents a local session from starting, failing with
`CONNECT_URL_NOT_SET`. It must be uninstalled and the runtime restarted before
Spark will initialise locally. This is not an issue in the devcontainer.

Run all cells in order. The alert table is written to `output/alerts` as
Parquet.

---

## AI usage disclosure

**Tool used:** Claude (Anthropic), via the chat interface.

**What I used it for:** Environment setup, code debugging and review.

**Example prompts:**
- "Help me create a Colab notebook step by step for this detection quest"
- "I get an import error in cell 3" (with the traceback pasted)
- "Here are all 16 DNS events - which one is the detection?"
- "Should I do this in pandas as well, or stick with PySpark?"
- "Are you sure the queries are correct? We were facing errors previously"

**Where it helped:**
- Diagnosing a Colab-specific environment problem: the preinstalled dataproc-spark-connect package patches SparkSession.builder into Spark Connect mode and blocks a local session. This took several rounds to isolate and was not something I would have found quickly on my own.


**What was mine:** I ran and validated every cell, and supplied all the data code, queries and outputs the analysis was built on.I reviewed all DNS events individually rather than relying on a generated query to surface the answer. I verified the correctness claims in this submission against my own notebook output rather than taking the generated narrative at face value.
