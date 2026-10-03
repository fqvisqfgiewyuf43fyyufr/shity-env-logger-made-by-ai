# Env Logger v2

**Read this first: this tool is full of bugs, and using its output will get you detected and banned. See [Warnings](#warnings) below.**

A Python-based environment logger for Luau/Lua. It runs a script inside a
mocked Roblox-ish sandbox, records every global call it makes, and writes the
result back out as **reconstructable Lua** — so you read `print("hello")`
instead of a variable name, and get the literal arguments back instead of just
their output.

```lua
-- in:  local a = "Hello, world!"  print(a)
-- out: print("Hello, world!")
```

## Warnings

Read these before you do anything with this.

- **It is full of bugs.** It is one person's project, written to answer one
  person's questions. It will crash, produce truncated output, miss calls,
  log things that didn't happen, and hang on some scripts. There is no test
  suite covering your exact input. Verify anything important by hand.
- **It gets you detected.** The sandbox deliberately fakes executor globals
  and slips past anti-logger and anti-tamper checks, which is the only way to
  observe what a hostile script actually does. That makes it useful for
  analysis and useless as a safety net. If you feed its output anywhere near
  a live game, assume you will be caught. Use it on offline material only.
- **No warranty, no support, no guarantees of any kind.** See `LICENSE`.

## Do what you want with it

This is public domain. Take it, change it, break it, sell it, ship it inside
something else, whatever.

- **Use it however you want.** Personal, commercial, whatever. No permission
  needed, no restrictions.
- **Edit it freely.** Fork it, rewrite it, vendor it, delete half of it. It is
  one big Python file; there is nothing stopping you.
- **No credits required.** You do not have to credit me, mention me, or link
  back. Nobody will ask, and nobody cares. A "based on env logger" line is
  welcome but never expected.

The [Unlicense](LICENSE) is deliberate: it dedicates the work to the public
domain, which is the closest legal match to "do whatever, no credit." If you
would rather have a conventional license, MIT or Apache-2.0 are drop-in
replacements.

## Requirements

- Python 3.8+
- [Lune](https://github.com/lune-org/lune) — the Luau runtime this drives

```bash
winget install lune-org.lune          # Windows
cargo install lune                    # anywhere with Rust
```

If `lune` is on your `PATH`, it is found automatically. Otherwise point at it
with `--lune /path/to/lune`, or set `LUNE_EXE`; `~/.cargo/bin/lune` is also
checked, which is where `cargo install lune` puts it.

## Usage

### Quick start (Windows)

Drop the script you want to log into this folder as `script.lua` and
double-click **`run.bat`**. It runs this preset:

```
python env_logger.py script.lua -o logged.lua --no-fetched --timeout 360 --clean
```

| Preset flag | Why |
| --- | --- |
| `--no-fetched` | log the calls without dumping fetched payload sources |
| `--timeout 360` | up to 6 minutes, for scripts that take a while to unpack |
| `--clean` | keep only readable calls, drop VM junk |

Results land in `logged.lua` (reconstructed calls) and `logged.trace.lua` (raw
behaviour trace). `run.bat` changes into its own folder first, so it works no
matter where you launch it from, and it stops with a clear message if
`script.lua` is missing or still empty.

`script.lua` ships empty on purpose — it's your drop-in slot. **Note that it's
a tracked file**, so once you put your own script there git will see it as
modified. If you'd rather not risk committing the script you're analysing,
either delete it from the repo or add this line to `.gitignore`:

```
script.lua
```

### Everything else

```bash
# reconstruct a script's calls
python env_logger.py my_obfuscated.lua -o logged.lua

# clean output: drop wrapper noise and keep only the calls worth reading
python env_logger.py my_obfuscated.lua -o logged.lua --clean

# write the instrumented file without running it
python env_logger.py my_obfuscated.lua --no-run

# save the raw runtime trace as well
python env_logger.py my_obfuscated.lua -o logged.lua --trace-out trace.lua

# never touch the network
python env_logger.py my_obfuscated.lua -o logged.lua --no-net
```

Try it on the bundled example first — it is the fastest way to confirm your
install works:

```bash
python env_logger.py examples/hello_obfuscated.lua -o logged.lua --clean
```

```
print("Hello, world!")
print(246)
```

### Options

| Flag | What it does |
| --- | --- |
| `-o, --output PATH` | where to write the recovered payload source, directly executable (default `logged.lua`); falls back to the call trace when no payload was recovered |
| `--trace-out PATH` | also write the raw call trace — a behaviour log, *not* runnable Lua (default: `<output stem>.trace.lua`) |
| `--no-trace` | don't write the trace sidecar at all |
| `--lune PATH` | explicit path to the `lune`/`lua` binary (auto-detected if unset) |
| `--no-run` | only generate the instrumented file, don't execute it |
| `--timeout SEC` | execution time budget (default `30`) |
| `--no-net` | fully offline — no prefetch, no links. **This is the default** |
| `--net` | allow network prefetch/linking. Exfil sinks stay hard-blocked either way (see below) |
| `--no-fetch` | never simulate a fetch: `game:HttpGet` returns empty and `loadstring` runs whatever string it is actually handed |
| `--payload FILE` | serve `FILE`'s contents as the response to every `game:HttpGet` call (pair with `--no-fetch`) |
| `--repair-source` | fix unambiguous transcription corruption (unterminated strings, stray trailing chars, `(t)[k]=v` / `{t}.field` ambiguity) before wrapping; originals are never modified and every fix is printed |
| `--place-id ID` | emulate a specific place: `game.PlaceId` returns this (default `0` = no game) |
| `--game-id ID` | emulate `game.GameId` (default `0`, follows `--place-id`) |
| `--hide-executor-globals` | hide executor-only globals (`getgenv`, `getgc`, `syn`, `io`, `readfile`, …) — some anti-tamper samples need them absent |
| `--strict-members` | unknown Instance/Service members read as `nil` (real Roblox behaviour) instead of a catch-all callable stub |
| `--syn-body FILE` | fake `syn.request` success, returning `FILE`'s contents as the response `Body` |
| `--chunk-arg FILE` | pass `FILE`'s content (newline-separated Lua funcs, `loadstring`'d) as the wrapped chunk's vararg |
| `--prefetch-file FILE` | pre-fetch every `-- LINK: <url>` line found in `FILE` into the cache before the run |
| `--clean` | clean VM junk, payload only (the default is verbose) |
| `--no-filter` | alias for `--verbose` |
| `--no-full-source` | don't embed full payload source inline; dump it via the SECOND-STAGE section only |
| `--no-fetched` | don't show fetched payload contents at all (URLs and sizes are still logged) |
| `--auto-link` | if uncached `-- LINK:` lines appear, prefetch them and re-run automatically |
| `--report PATH` | write the full run report (console output + stats) alongside `-o` |
| `--json PATH` | write a machine-readable summary (lines/links/coverage/status) |
| `--verbose` | more runtime detail (prefetch attempts, executor, staged bytes) |

### Network behaviour, in both directions

Worth stating plainly, because the tool emulates an executor and that sounds
worse than it is.

**Outbound (script → internet): hard blocked, always.** Network sinks the
analysed script might reach for — `request`, `syn.*`, `net.*`, `HttpService`,
`require("@lune/net")` — record the attempt as `-- NETWORK BLOCKED` in the
trace and return an inert response. They never open a connection, under any
flag combination.

**Inbound (this tool → internet): opt-in, and it trusts the script.** With
`--net`, the tool fetches whatever URLs the script referenced, so you can
recover second-stage payloads. There is deliberately **no host allowlist** —
any host the script names gets fetched, which includes paste sites, discords,
and bare IPs. Only use `--net` on material you trust. `--no-net` is the
default, and without it every link resolves to empty.

## How it works

1. Python prepends a logging header (UNC/executor-global emulation, `_G` proxy,
   mocked Roblox API surface) to your script.
2. Global functions are wrapped — `print`, `warn`, `string.char`, and so on —
   so each call is recorded as `name(repr(args))`.
3. Executor globals the sandbox needs (`getgenv`, `getrenv`, `hookfunction`,
   `checkcaller`, …) are stubbed so scripts that probe for them behave
   normally instead of erroring out.
4. The wrapped file runs in a Lune subprocess.
5. The `--- ENV LOGGER DUMP START ---` block is captured and cleaned into
   readable Lua.

## Limitations

These are structural, not bugs, and worth knowing up front:

- **Control flow is not recovered.** `while`/`if`/`repeat` structure stays
  hidden inside whatever VM the obfuscator used. You get calls, not logic.
- **Log volume is capped.** Huge loops get truncated.
- **No decompiler.** A custom VM obfuscator still needs a real deobfuscator;
  this only tells you what the script *does*.
- **Probing costs time.** Anti-tamper scripts burn their time budget on
  fingerprint loops before doing anything interesting.
- **Mocked values are inert.** Anything that depends on real engine behavior
  takes a different branch than it would in a live game.

## Repository layout

```
env_logger.py                     the whole tool
run.bat                           Windows one-click runner
examples/hello_obfuscated.lua     tiny hand-written demo
LICENSE                           Unlicense (public domain)
```

## Contributing

Not required and not tracked — it's a one-file project with no roadmap. If you
send a PR, keep it to `env_logger.py` and make sure the example above still
prints those two lines.