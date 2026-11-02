# SA-warn — `| warn` search command

Shows a custom message under the search bar, optionally only when a condition
holds. Results pass through unchanged.

```spl
index=foo | ... | warn "This dataset is incomplete before 2026-10-01"
| stats count | warn if="count = 0" level=error "No data: do not use this report"
| stats dc(host) as hosts | eval msg="Only " . hosts . " hosts reported" | warn if="hosts < 10" field=msg
```

## Syntax

```
warn [if=<condition>] [level=warn|error|info] ( "<text>" | message="<text>" | field=<field> )
```

| Option | Meaning |
|---|---|
| `"<text>"` | Literal text. Quote it if it contains `=` (otherwise `name=value` is read as an option). |
| `message="<text>"` | Same, explicitly. |
| `field=<field>` | The message is the value of this field (multivalue joined with `, `). A field is only ever read through `field=`. |
| `if=<condition>` | Show the message only if **at least one** result satisfies the condition. With `field=`, the first such result is used. Quote the condition if it contains spaces: `if="count > 1000"`. |
| `level=` | `warn` (default, yellow banner), `info` (only in the Job menu and the Job Inspector), `error` (**stops the search**, see below). |

Without `if=`, the message is always shown, even when there are no results
(except with `field=`, which needs a result to read).

### `level=error` stops the search

With `level=error`, when the message fires the search stops: no result passes
`| warn`, and the message is shown as an error. Use it as a guard, so that a
report or a dashboard never shows misleading numbers.

* Splunk 10.x: the search fails (`Error in 'warn' command: <message>`).
* Splunk 9.x: the search completes with no results and a red banner; commands
  after `| warn` run on an empty set (`stats count` returns 0).

Splunk 10 turns any error message of a custom command into a failed search, so
a non-blocking red banner is not possible there; `level=error` behaves as a
stop on every version for consistency.

## In dashboards

Panels show the message behind an icon in the panel header, not as a banner:

| Level | Classic (Simple XML) | Dashboard Studio |
|---|---|---|
| `warn` | yellow icon, text on click | icon, text on click |
| `error` | 10.x: the panel shows the error instead of results. 9.x: red icon with the message, "No results found." | 10.x: the panel shows the error instead of results. 9.x: "No search results returned", the message is not shown |
| `info` | not shown | not shown |

Use `level=warn` to inform dashboard users, `level=error` to block the panel. In a dashboard, `$` is
the token delimiter: write `$$` for a literal dollar sign.

## Conditions

`if=` accepts a subset of the `where` syntax, evaluated by the command itself:

* operators `= == != < > <= >=`, `AND OR NOT XOR`, `LIKE`, `IN (...)`, `+ - * / % .`, parentheses;
* field names, `'quoted field names'`, `"strings"`, numbers;
* functions: `if case coalesce in like match cidrmatch isnull isnotnull isnum isint isstr
  null true false len lower upper trim ltrim rtrim substr replace tostring tonumber abs
  round floor ceiling ceil sqrt pow min max mvcount now`.

Any other function is refused with an explicit error. For anything beyond the
subset, compute it with `eval` first:

```spl
| eval stale=if(_time < relative_time(now(), "-1d"), 1, 0) | warn if="stale=1" "Data older than one day"
```

Known differences with `where`:

* `match()` uses Python regular expressions, not PCRE (rare syntax may differ).
* An empty field value is null: the search protocol does not distinguish an
  empty value from a missing field.
* Splunk refuses some type mismatches before running the search; the command
  refuses the obvious ones (`"1"=1`, `"9"+1`) and otherwise evaluates them as null.

## Security

* No network access, no file written, no Python `eval`: the condition is parsed
  and evaluated by a small dedicated interpreter.
* Messages are reduced to one line, control and bidirectional-override
  characters are removed, length is capped at 1024 characters. The Search page
  of Splunk Web escapes HTML in search messages.

## Requirements

Splunk Enterprise 9.x (Python 3.9) and 10.x / Splunk Cloud (Python 3.13). Tested on 9.3.14 and 10.2.8.
Bundles splunklib 3.0.1 (Apache 2.0, see `bin/lib/NOTICE`).

## License

Copyright 2026 the SA-warn authors. Licensed under the Apache License,
Version 2.0 (see `LICENSE`). The bundled splunklib is also under the Apache
License 2.0 (see `bin/lib/NOTICE` and `bin/lib/LICENSE`).
