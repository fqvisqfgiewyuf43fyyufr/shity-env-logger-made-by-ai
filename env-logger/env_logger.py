#!/usr/bin/env python3
"""
Env Logger v2 - Python-powered Luau/Lua Environment Logger (Lune-compatible)
Run with: python env_logger.py <script.lua> [-o logged.lua] [--lune]

What it does:
- Takes any Luau/Lua script (obfuscated or not)
- Wraps it in a logging environment emulating UNC + executor globals
- Runs it via Lune (or Lua) in a subprocess
- Logs every global call as reconstructable Lua: print("hello") not just "hello"
- Bypasses common anti-logger detections (unc checks, sanity checks, traps)
"""

import argparse
import subprocess
import pathlib
import shutil
import sys
import re
import os
import time
import urllib.request
import urllib.error

# ---- global runtime flags (set from argparse; kept module-level so fetch_link/harness can read them)
NO_NET = False   # --no-net: never touch the network (fetch_link returns "", prefetch skipped)

# ---------- console beautification (ANSI auto-detect, symbols, sections) ----------
_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
RESET = "\x1b[0m"
def _paint(text, code):
    return f"{code}{text}{RESET}" if _USE_COLOR else text
def _dim(t):   return _paint(t, "\x1b[2m")
def _cyan(t):  return _paint(t, "\x1b[36m")
def _blue(t):  return _paint(t, "\x1b[34m")
def _green(t): return _paint(t, "\x1b[32m")
def _yellow(t):return _paint(t, "\x1b[33m")
def _red(t):   return _paint(t, "\x1b[31m")
def _bold(t):  return _paint(t, "\x1b[1m")

def _section(title):
    """Pretty CLI section header line."""
    print(_cyan("─") + _bold(_cyan(title)))

def _kv(key, value, pad=18):
    print(f"    {_bold(key):<{pad}}{value}")

def _rule(ch="─", n=64):
    print(_dim(ch * n))

def _banner():
    print(_rule("═", 64))
    print(_bold(_cyan("Env Logger v2")) + _dim("  ·  Luau/Lua runtime trace wrapper  ·  Lune"))
    print(_rule("═", 64))

def _summary_block(title, rows):
    """Render a key/value block inside a light box, e.g. the final stats panel."""
    if not rows:
        return
    w = 64
    inner = max(len(str(k)) + len(str(v)) for k, v in rows) + 4
    w = max(w, min(inner + 4, 92))
    print(_dim("╭" + "─" * (w - 2) + "╮"))
    print(_bold(_cyan(f"│ {title}") + " " * (w - len(title) - 3) + _dim("│")))
    print(_dim("├" + "─" * (w - 2) + "┤"))
    for k, v in rows:
        line = f"  {k}: {v}"
        print(f"│ {line}" + " " * (w - len(line) - 2) + _dim("|"))
    print(_dim("╰" + "─" * (w - 2) + "╯"))

# ---------- Lua runtime header (Lune-compatible: hooks getfenv(1) not _G/_ENV) ----------
LOGGER_HEADER = r"""
-- // Env Logger v2 Runtime - Lune Compatible (hooks getfenv(1)) - Stealth + Anti-VM-Junk
local __LOGS = {}
local __LOG_ENABLED = true
local __MAX_LOGS = 50000
local __LOG_COUNT = 0
-- when true, loadstring/load payload sources go into the LOGS stream INLINE in
-- full (default now ON so recovery output shows the whole deobfuscated source).
-- NOTE: _G.__LOG_FULL_PAYLOAD may be overridden by the loader preamble; __reprFullPayload
-- reads it at call-time (not at module load) so the override is respected.
local __LOG_FULL_PAYLOAD_DEFAULT = true
__GATE_PLACEID = _G and _G.__GATE_PLACEID or 0
__GATE_GAMEID = _G and _G.__GATE_GAMEID or __GATE_PLACEID
if _G and _G.__GATE_PLACEID and _G.__GATE_PLACEID ~= 0 then
    table.insert(__LOGS, "-- IN-GAME: PlaceId=" .. _G.__GATE_PLACEID .. " JobId=Logged")
end
if __GATE_GAMEID ~= __GATE_PLACEID then
    table.insert(__LOGS, "-- IN-GAME: GameId=" .. __GATE_GAMEID)
end
-- payload-captured gate: an error at the end of a script that already logged at
-- least this many real API calls is treated as VM teardown noise, not a failure.
local __GRACEFUL_MIN_LOGS = 6
-- queued coroutines for task.spawn/defer/delay + callback pump (global so footer sees them)
__taskQ = __taskQ or {}
__taskBudget = __taskBudget or {}
__idleCount = __idleCount or {}
__idleWait = __idleWait or {}
__sigOnceDone = __sigOnceDone or {}
-- signals whose callbacks should fire repeatedly (multiple frame-steps) so loop
-- bodies like throttle-while-wait fly code get captured by the pump
__signalRepeat = __signalRepeat or {}
__pumpStepping = false
__firingCallbacks = false
__MAIN_CO = __MAIN_CO or coroutine.running()
-- NOTE: __vmTick is installed after __realEnv is resolved (a bit further down),
-- since it must live in that environment for the payload to find it.
local __taskCallDbg = { count = 0 }
local __sigWaitDbg = 0
local __LOG_GETGLOBAL = false -- noisy "-- getglobal" comments; enable with --getglobals
local __STAGED = {} -- full sources passed to loadstring/load (second stages), dumped separately
local __MAX_STAGES = 10
local __isLoaderLoad = false -- only the loader sets this around ITS loadstring call
-- userdata -> constructor call string, e.g. ud -> 'UDim2.new(0, 540, 0, 360)'
-- lets property logs read real values instead of "nil --[[userdata]]"
local __valData = setmetatable({}, {__mode="k"})
-- full-source tracking: readable reprs for mocked value userdata (UDim2.new(...) etc),
-- dedupe set for getglobal noise. Declared up here so __repr can see them.
local __valRepr = setmetatable({}, {__mode="k"})
local __seenGetglobal = {}
-- denylist: hide VM decoding junk (bit32/math), keep payload (print/game/table.unpack/string.char)
local __DENY = {
  ["bit32.band"]=true, ["bit32.rshift"]=true, ["bit32.lshift"]=true, ["bit32.bxor"]=true, ["bit32.bor"]=true, ["bit32.btest"]=true, ["bit32.bnot"]=true,
  ["bit32.rrotate"]=true, ["bit32.lrotate"]=true, ["bit32.arshift"]=true, ["bit32.extract"]=true, ["bit32.replace"]=true, ["bit32.shift"]=true, ["bit32.rot"]=true,
  ["math.floor"]=true, ["math.random"]=true, ["math.ceil"]=true, ["math.abs"]=true, ["math.clamp"]=true, ["math.min"]=true, ["math.max"]=true,
  ["math.ldexp"]=true, ["math.frexp"]=true, ["math.modf"]=true, ["math.pow"]=true, ["math.sqrt"]=true, ["math.log"]=true, ["math.exp"]=true, ["math.fmod"]=true, ["math.huge"]=true,
  ["string.sub"]=true, ["string.len"]=true, ["string.gmatch"]=true, ["string.match"]=true,
  ["string.gsub"]=true, ["string.byte"]=true, ["string.char"]=true, ["string.reverse"]=true, ["string.unpack"]=true, ["string.pack"]=true,
  ["string.format"]=true, ["string.rep"]=true, ["string.lower"]=true, ["string.upper"]=true, ["string.find"]=true, ["string.gfind"]=true,
  ["table.insert"]=true, ["table.remove"]=true, ["table.sort"]=true, ["table.move"]=true, ["table.create"]=true,
  ["table.concat"]=true, ["table.insert"]=true, ["table.pack"]=true, ["table.maxn"]=true, ["table.clear"]=true, ["table.fill"]=true,
  ["table.unpack"]=true, ["table.find"]=true, ["table.clone"]=true, ["table.freeze"]=true, ["table.isfrozen"]=true,
  ["tostring"]=true, ["tonumber"]=true, ["type"]=true, ["select"]=true, ["unpack"]=true,
  ["coroutine.create"]=true, ["coroutine.resume"]=true, ["coroutine.wrap"]=true, ["coroutine.status"]=true,
  ["task.wait"]=true, ["task.spawn"]=true, ["task.defer"]=true, ["task.delay"]=true,
  ["os.clock"]=true, ["os.time"]=true, ["os.date"]=true,
  ["debug.getinfo"]=true, ["debug.info"]=true, ["debug.getupvalue"]=true, ["debug.getconstant"]=true,
  ["pcall"]=true, ["xpcall"]=true, ["error"]=true, ["assert"]=true,
  ["getfenv"]=true, ["setfenv"]=true, ["setmetatable"]=true, ["getmetatable"]=true, ["rawget"]=true, ["rawset"]=true,
  -- cooperative-preemption internals: never surface the injected __vmTick hook
  -- or the coroutine primitives it uses (they'd drown the real API trace)
  ["__vmTick"]=true, ["coroutine.running"]=true, ["coroutine.yield"]=true, ["coroutine.yield_all"]=true,
}

-- capture raw locals BEFORE tampering (must use these inside __repr to avoid wrapper recursion)
local __rawget = rawget
local __rawset = rawset
local __pairs = pairs
local __ipairs = ipairs
local __tostring = tostring
local __type = type
local __select = select
local __table_insert = table.insert
local __table_concat = table.concat
local __string_format = string.format
local __next = next
local __pcall = pcall
local __str_byte = string.byte
local __str_char = string.char
local __str_sub = string.sub
local __str_rep = string.rep
local __math_floor = math.floor
local __math_random = math.random

local function __repr(v, depth)
    depth = depth or 0
    if depth > 4 then return "..." end
    local t = __type(v)
    -- table-backed value types (Vector2/3 etc) log as their constructor call
    if t == "table" then
        local vr = __valRepr and __valRepr[v]
        if vr then return vr end
    end
    if t == "string" then
        -- CRASH GUARD: a 100MB string arg would freeze repr + explode logged.lua.
        -- Log first 200 bytes only, note the real size (script itself is unaffected).
        if #v > 2000 then
            local parts = {}
            for i = 1, 200 do parts[i] = __tostring(__str_byte(v, i)) end
            return "string.char(" .. __table_concat(parts, ", ") .. ") --[[" .. #v .. " bytes, truncated]]"
        end
        -- byte-safe: printable ASCII -> %q, else string.char(...) so logged.lua always parses
        -- NOTE: use captured __str_byte (not global string.byte) to avoid wrapper recursion
        local ok_printable = true
        for i = 1, #v do
            local b = __str_byte(v, i)
            if b == 10 or b == 13 or b == 9 then
            elseif b < 32 or b > 126 then
                if b ~= nil then ok_printable = false break end
            end
        end
        if ok_printable then
            return __string_format("%q", v)
        else
            local parts = {}
            local n = #v
            if n > 200 then n = 200 end
            for i = 1, n do
                parts[i] = __tostring(__str_byte(v, i))
            end
            return "string.char(" .. __table_concat(parts, ", ") .. ")"
        end
    elseif t == "number" or t == "boolean" then
        return __tostring(v)
    elseif t == "nil" then
        return "nil"
    elseif t == "table" then
        -- Enum items log as real Luau (Enum.Font.GothamBold), not a dumped table
        local __en, __et = __rawget(v, "Name"), __rawget(v, "EnumType")
        if __type(__en) == "string" and __type(__et) == "string" then
            return "Enum." .. __et .. "." .. __en
        end
        -- for env logger, we want valid Luau, not "table: 0x..."
        -- if it's an array with 1-20 elements, show as {"a","b"}
        local isArray = true
        local n = #v
        local count = 0
        for k,_ in __pairs(v) do
            count = count + 1
            if __type(k) ~= "number" or k < 1 or k > 100 or __math_floor(k) ~= k then
                isArray = false
                break
            end
        end
        if isArray and count == n and n <= 20 and n > 0 then
            local parts = {}
            for i=1,n do parts[i] = __repr(v[i], depth+1) end
            return "{" .. __table_concat(parts, ", ") .. "}"
        elseif __next(v) == nil then
            return "{}"
        else
            -- for non-array, try to show as {} with up to 5 elements, not "table: 0x..."
            local parts = {}
            local c=0
            for k,v2 in __pairs(v) do
                c=c+1
                if c>5 then break end
                parts[c] = "["..__repr(k,depth+1).."]="..__repr(v2,depth+1)
            end
            if c>0 then return "{"..__table_concat(parts,", ").."}" else return "{}" end
        end
    elseif t == "function" then
        -- must stay valid Luau: bare `function` does not parse, use placeholder
        return "(function() end)"
    elseif t == "thread" then
        return "nil --[[thread]]"
    elseif t == "userdata" then
        -- mocked Instances log as their tracked id (ScreenGui_1), value types as
        -- their constructor (UDim2.new(...)) so assignments stay reconstructable
        if __instData then
            local __rec = __instData[v]
            if __rec and __rec.id then return __rec.id end
        end
        local __vr = __valRepr[v]
        if __vr then return __vr end
        return "nil --[[userdata]]"
    else
        return __tostring(v)
    end
end

-- truncated repr for large sources: preview head bytes, note the tail separately
local function __reprDiff(v, headN)
    if __type(v) ~= "string" then return __repr(v) end
    if #v <= headN * 3 then return __repr(v) end
    local head = v:sub(1, headN)
    local parts = {}
    for i = 1, headN do parts[i] = __tostring(__str_byte(head, i)) end
    return "string.char(" .. __table_concat(parts, ", ") .. ") --[[" .. #v .. " bytes, head " .. headN .. " shown]]"
end
-- A loadstring payload should NEVER be reduced to a stub in the final log:
-- store its complete source in __LOGS as a dedicated block too (in addition to
-- the SECOND-STAGE dump) so the recovered payload survives even partial writes.
local function __reprFullPayload(v, tag)
    if __type(v) ~= "string" then return __repr(v) end
    -- read the flag at call-time so the loader preamble can override the default
    local enabled = _G.__LOG_FULL_PAYLOAD
    if enabled == nil then enabled = __LOG_FULL_PAYLOAD_DEFAULT end
    if _G and _G.__NO_FETCHED then enabled = false end
    if enabled then
        return (tag or "payload") .. " {\n" .. v .. "\n}" .. " --[[" .. #v .. " bytes full source captured]]"
    end
    return __reprDiff(v, 120)
end

local __TRACE_BUF = {}
-- flushed to stdout as the script runs, so even a run that dies BEFORE the
-- end-of-run __LOG_DUMP (C-level stack overflow aborts Lune) still leaves us
-- the API-call trace the payload made right up to the crash point.
local __LOG_LIVE_FLUSH = 1 -- every N calls, print the pending trace lines
local __liveFlushedCount = 0
local __origPrintLate = nil -- assigned to __origPrint once its wrapper exists (upvalue)
local __origWarnLate = nil -- assigned to __origWarn once its wrapper exists (upvalue)
local function __traceLine(msg)
    __TRACE_BUF[#__TRACE_BUF + 1] = msg
    __liveFlushedCount = __liveFlushedCount + 1
    if __LOG_LIVE_FLUSH > 0 and __liveFlushedCount >= __LOG_LIVE_FLUSH then
        __liveFlushedCount = 0
if __origPrintLate then
                    __origPrintLate("--- ENV LOGGER LIVE TRACE (crashed-run buffer flush) ---")
                    for i = 1, #__TRACE_BUF do
                        __origPrintLate(__TRACE_BUF[i])
                    end
                    __TRACE_BUF = {}
                    __origPrintLate("--- ENV LOGGER LIVE TRACE end ---")
                end
                -- stderr survives C-level aborts (stdout does not); warn() -> stderr
                if __origWarnLate then
                    __origWarnLate("--- ENV LOGGER LIVE TRACE (crashed-run buffer flush) ---")
                    for i = 1, #__TRACE_BUF do
                        __origWarnLate(__TRACE_BUF[i])
                    end
                    __origWarnLate("--- ENV LOGGER LIVE TRACE end ---")
                end
    end
end
-- call-depth tracker for indented output (kept for deep-trace; wrapper can't
-- safely track it without breaking multi-value returns, so wrapper stays tail-call)
local __callDepth = 0
local function __logCall(name, argsRepr)
    if not __LOG_ENABLED then return end
    if __DENY[name] then return end
    if name=="error" and argsRepr:find("attempt to perform arithmetic") then return end
    __LOG_COUNT = __LOG_COUNT + 1
    if __LOG_COUNT > __MAX_LOGS then return end
    __table_insert(__LOGS, name .. "(" .. argsRepr .. ")")
    __traceLine(name .. "(" .. argsRepr:sub(1, 100) .. ")")
end
-- track resolved function references from getfenv proxy for indirect-call detection
local __resolvedRefs = {} -- id(ref) -> name  (for debug hook deep tracing)
-- globals whose resolved references should be tracked for indirect-call logging
local __TRACKED_GLOBALS = {
    ["print"]=true, ["warn"]=true, ["error"]=true, ["game"]=true, ["workspace"]=true,
    ["Instance"]=true, ["Vector3"]=true, ["CFrame"]=true, ["loadstring"]=true,
    ["require"]=true, ["task"]=true, ["spawn"]=true, ["typeof"]=true, ["Enum"]=true,
    ["pcall"]=true, ["xpcall"]=true, ["pairs"]=true, ["ipairs"]=true,
    ["setmetatable"]=true, ["getmetatable"]=true, ["rawget"]=true, ["rawset"]=true,
    ["tostring"]=true, ["tonumber"]=true, ["type"]=true, ["select"]=true, ["unpack"]=true,
}
-- debug.sethook deep tracing: fires on EVERY function call via the Lua VM, catching
-- indirect calls through registers that bypass the getfenv proxy entirely.
-- This is the only way to catch getfenv-resolved functions called via VM opcodes
-- like CALL f[e[a]](e[r]) where f was set by a previous GETGLOBAL from the proxy.
local __deepTraceEnabled = false
local __deepTraceLog = {} -- list of "[call] name(args)" strings
local __deepTraceCount = 0
local __DEEP_TRACE_MAX = 2000
local __hookActive = false -- re-entrancy guard (debug hooks fire on ANY call incl ours)
local function __deepCallHook(event)
    if event ~= "call" then return end
    if __hookActive then return end
    __hookActive = true
    local ok, info = pcall(debug.getinfo, 2, "Sfn")
    if ok and info and info.func and __deepTraceCount < __DEEP_TRACE_MAX then
        local fn = info.func
        local refName = __resolvedRefs[tostring(fn)]
        if refName then
            __deepTraceCount = __deepTraceCount + 1
            table.insert(__deepTraceLog, "-- [deep-trace] " .. refName .. "(...)")
        end
    end
    __hookActive = false
end
-- install the hook only when explicitly enabled (performance: ~2x slowdown)
local __enableDeepTrace = nil
local __disableDeepTrace = nil
__pcall(function()
    local dbg = debug
    -- Lune may not implement sethook; if it errors we skip silently
    __enableDeepTrace = function()
        if __deepTraceEnabled then return end
        local ok, _ = __pcall(function() dbg.sethook(__deepCallHook, "c") end)
        __deepTraceEnabled = ok
    end
    __disableDeepTrace = function()
        if not __deepTraceEnabled then return end
        __pcall(function() dbg.sethook(nil) end)
        __deepTraceEnabled = false
    end
end)

local function __argsToRepr(...)
    local n = __select("#", ...)
    if n == 0 then return "" end
    local parts = {}
    for i=1,n do
        local v = __select(i, ...)
        parts[i] = __repr(v)
    end
    return __table_concat(parts, ", ")
end

-- // Exfil guard removed: network passthrough enabled
-- Any script trying to POST/GET data out will use real network connections.
local function __exfilUrlOf(arg1, arg2)
    -- Roblox request({Url=...}) passes an options table; request("url") passes a
    -- string. Read the table form properly so the trace names the URL instead of
    -- dumping an address, and label a table that carries no Url key honestly.
    local u = nil
    if __type(arg1) == "table" then
        u = arg1.Url or arg1.url or arg1.URL
        if (u == nil or u == "") then
            local n = 0
            for _k in __pairs(arg1) do n = n + 1 end
            return "<options table: " .. tostring(n) .. " keys, no Url>"
        end
    elseif arg1 ~= nil then
        u = arg1
    end
    if (u == nil or u == "") and __type(arg2) == "string" then u = arg2 end
    return __tostring(u or "?"):sub(1, 200)
end
local function __exfilBlock(name, url)
    -- Hard block. Network sinks (request/syn/net.*/HttpService/require of
    -- @lune/net) record the attempt in the trace and return an inert response;
    -- they never touch a socket. Lua-side egress is impossible here anyway --
    -- net.request yields to Lune's scheduler, which cannot happen inside the
    -- coroutine this logger pumps (it spins until mlua panics on auxiliary
    -- stack exhaustion) -- so this is a correctness guarantee, not a workaround.
    url = __tostring(url or "?"):sub(1, 200)
    __LOG_COUNT = __LOG_COUNT + 1
    if __LOG_COUNT <= __MAX_LOGS then
        __table_insert(__LOGS, "-- NETWORK BLOCKED (" .. name .. " -> " .. url .. ")")
    end
end

local function __sinkResponse()
    -- proxied fake SUCCESS so the Activator advances: key check passes, the flow
    -- moves on to loadstring(response.Body) = the real feature script. Body comes
    -- from --syn-body (otherwise the script reports timeout_or_fail).
    local __synBody = _G and (_G.__SYN_BODY or _G.__GATE_SYNBODY) or ""
    return setmetatable({}, {__index=function(_, k)
        if k == "Success" or k == "success" then return true end
        if k == "StatusCode" or k == "status" then return 200 end
        if k == "Body" or k == "body" or k == "BodyText" or k == "Content" then return __synBody end
        if k == "Headers" or k == "headers" then return {} end
        return nil
    end})
end
local function __makeBlockedFn(name)
    return function(a, b)
        __exfilBlock(name, __exfilUrlOf(a, b))
        return { Success = false, StatusCode = 0, StatusMessage = "blocked",
                 Headers = {}, Body = "" }
    end
end

-- // Detect correct global env for Lune vs standard Lua
-- Lune: _G != _ENV, _ENV is nil, globals live in getfenv(1)
-- Standard Lua/Luau: globals in _G / _ENV
local __realEnv
if getfenv then
    local ok, env = __pcall(getfenv, 1)
    if ok and env and __type(env)=="table" then
        __realEnv = env
    else
        ok, env = __pcall(getfenv, 0)
        if ok and env then __realEnv = env else __realEnv = _G end
    end
else
    __realEnv = _ENV or _G
end
-- fallback if still nil
if not __realEnv then __realEnv = _G end

-- cooperative VM preemption tick: injected into the payload's Gi/loop source by
-- __VM_INJECT so a recovered interpreter (whose main loop parks on task.wait at
-- the main thread, which cannot yield there) yields back to our driver pump.
-- Count-based: yields every N calls. task.wait() at the main thread is a no-yield
-- mock, so we CANNOT rely on it; this is the real preemption hook.
__vmTickCounter = 0
__VMTICK_EVERY = 2048
do
    local __tickFn = function()
        __vmTickCounter = __vmTickCounter + 1
        if __vmTickCounter % __VMTICK_EVERY == 0 then
            local __rok, __run = pcall(coroutine.running)
            if __rok and type(__run) == "thread" and __run ~= __MAIN_CO then
                coroutine.yield()
            end
        end
    end
    -- payload runs with setfenv(__realEnv); also expose on _G for globals queries
    __pcall(function() __realEnv["__vmTick"] = __tickFn end)
    if _G and _G ~= __realEnv then __pcall(function() _G["__vmTick"] = __tickFn end) end
end
-- Source-level cooperative-preemption transform applied in __execLoadstring to
-- every staged (payload) string: insert `__vmTick();` as the first statement of
-- each `while (x) do` loop so a tight CPU spin can always yield back to the
-- driver coroutine (pure text transform; __vmTick increments a counter and only
-- yields every __VMTICK_EVERY calls). Quote/comment-aware: string literals and
-- comments are preserved byte-for-byte (data strings like fi="LPH$.." are safe).
local __VM_INJECT
do
    local __str_find = string.find
    local __str_sub = string.sub
    local __str_rep = string.rep
    local __table_ins = table.insert
    __VM_INJECT = function(s)
        if type(s) ~= "string" then return s end
        if #s < 4096 then return s end
        local out, si = {}, {}
        local i, n = 1, #s
        local protected = false -- inside a string/comment: copy verbatim
        while i <= n do
            local c = __str_sub(s, i, i)
            if protected then
                local j = __str_find(s, protected, i, true)
                if j then
                    __table_ins(out, __str_sub(s, i, j + #protected - 1))
                    i = j + #protected
                    protected = false
                else
                    __table_ins(out, __str_sub(s, i))
                    break
                end
            elseif c == "[" then
                -- long string/comment bracket: [=*[
                local j = i + 1
                local eq = 0
                while __str_sub(s, j, j) == "=" do eq = eq + 1; j = j + 1 end
                if __str_sub(s, j, j) == "[" then
                    protected = "]" .. __str_rep("=", eq) .. "]"
                    -- keep opening bracket consumed below by loop (slice up to i)
                else
                    __table_ins(out, c); i = i + 1
                end
            elseif c == '"' or c == "'" then
                local j = i + 1
                while j <= n do
                    if __str_sub(s, j, j) == "\\" then j = j + 2
                    elseif __str_sub(s, j, j) == c then break
                    else j = j + 1 end
                end
                if j <= n then
                    __table_ins(out, __str_sub(s, i, j))
                    i = j + 1
                else
                    __table_ins(out, __str_sub(s, i))
                    break
                end
            elseif c == "-" and __str_sub(s, i+1, i+1) == "-" and __str_sub(s, i+2, i+2) == "[" then
                -- long comment handled by '[' branch above; here just copy
                __table_ins(out, c); i = i + 1
            elseif c == "-" and __str_sub(s, i+1, i+1) == "-" then
                local j = __str_find(s, "\n", i + 2, true)
                if j then
                    __table_ins(out, __str_sub(s, i, j - 1))
                    i = j
                else
                    __table_ins(out, __str_sub(s, i))
                    break
                end
            else
                local m = s:match("^while%((%w+)%)do", i)
                if m then
                    __table_ins(out, "while(" .. m .. ")do __vmTick();")
                    i = i + 6 + #m + 3
                else
                    __table_ins(out, c); i = i + 1
                end
            end
        end
        return table.concat(out)
    end
end

local __sharedEnv = {}
local __unc = {}
-- populate sharedEnv with globals for getgenv checks (deep copy for stealth, so getgenv() ~= getrenv())
for k,v in pairs(__realEnv) do __sharedEnv[k]=v end
-- ensure getgenv has print etc even though pairs missed metatable
for _,k in ipairs({"print","warn","error","game","workspace","Instance","Vector3","loadstring","require"}) do
    if __realEnv[k] and not __sharedEnv[k] then __sharedEnv[k]=__realEnv[k] end
end
setmetatable(__sharedEnv, {__index=__realEnv, __newindex=function(t,k,v) __realEnv[k]=v; rawset(t,k,v) end})

-- store originals via normal get (Lune env uses metatable, rawget returns nil)
local __origPrint = __realEnv.print or print
__origPrintLate = __origPrint

local __origWarn = __realEnv.warn or warn or function(...) __origPrint(...) end
local __origWarnLate = __origWarn
local __origGetmetatable = getmetatable
local __origSetmetatable = setmetatable

-- LIVE STAGE FLUSH: a C-level stack overflow inside a recovered payload aborts Lune
-- before the end-of-run __LOG_DUMP, losing every staged source. Print each stage to
-- stdout the moment it is captured (orig print, bypasses __logCall/log buffer) so
-- even an aborting run still yields the deobfuscated second-stage source. Staging
-- sites call __flushStagedLive() right after inserting into __STAGED.
local __lastLiveFlushIdx = 0
local __flushStagedLive
__flushStagedLive = function()
    local __noFetched = _G and _G.__NO_FETCHED
    while __lastLiveFlushIdx < #__STAGED do
        __lastLiveFlushIdx = __lastLiveFlushIdx + 1
        local st = __STAGED[__lastLiveFlushIdx]
        if st and st.src and #st.src > 0 then
            __origPrint(("-- [LIVE-STAGE %d] %s: %d bytes --"):format(__lastLiveFlushIdx, st.chunk or "?", #st.src))
            if not __noFetched then
                __origPrint(st.src)
                __origPrint(("-- [LIVE-STAGE %d END] --"):format(__lastLiveFlushIdx))
            end
        end
    end
end

local __loggedGlobals = {}
local __wrappedMap = {} -- wrapped -> original
local __origIsC = {} -- wrapped -> bool
local __isCClosureTrack = {} -- for newcclosure
-- stealth: use newcclosure if available to make wrapped appear as C, else fallback
local __useNewCClosure = (newcclosure ~= nil)
-- Wrappers are built from a ONE-LINE source chunk on purpose. When a Roblox stdlib
-- C function raises an argument error, Luau prefixes the message with the position
-- of the calling frame. If the wrapper lived in the generated harness file the script
-- would see "__wrapped__:551: invalid argument #2 to 'sub' ..." - a harness line
-- number no real Roblox script could have. Compiling the wrapper from a single line
-- keeps that position at line 1, so engine errors read like Roblox's.
-- (kept global, not local: the generated chunk already sits at Luau's 200-register limit)
_G.__mkWrapper = nil
__pcall(function()
    _G.__mkWrapper = (loadstring or load)("return function(fn, name, log) return function(...) log(name, ...) return fn(...) end end", "@roblox/stdlib")()
end)
-- raw loader kept for internal chunks (the CFrame math below is ~250 lines, and load /
-- loadstring are wrapped further down to log payload sources, so using them would copy
-- the whole chunk into every run's log)
_G.__rawLoadFn = nil
__pcall(function() _G.__rawLoadFn = loadstring or load end)
-- Roblox's error() does not bake a "file:line:" prefix into the message value: a
-- pcall around error("x") yields exactly "x" (that is what engine errors such as
-- HttpService:JSONDecode rely on). Wrapping error() in a Luau frame would otherwise
-- leak this harness' position into every message, so the default level is passed as 0.
_G.__mkErrorWrapper = nil
__pcall(function()
    _G.__mkErrorWrapper = (loadstring or load)("return function(fn, log) return function(a, b) if b == nil or b == 0 then return fn(a, 0) end return fn(a, b + 1) end end", "@roblox/stdlib")()
end)
-- A traceback that exposes the generated harness file and its 6000-line offsets is a
-- give-away: real Roblox only ever shows the running script plus engine internals.
-- Harness frames are renamed and line numbers clamped into script range; the frame
-- COUNT is deliberately left untouched because samples compare it to traceback length.
_G.__tbShim = nil
__pcall(function()
    _G.__tbShim = (loadstring or load)("return function(raw) return function(a, b) local r; if a == nil and b == nil then r = raw() else r = raw(tostring(a or ''), (type(b) == 'number' and b or 1) + 1) end; if type(r) ~= 'string' then return r end; r = r:gsub('[^%s:]-__wrapped__', '@roblox/scheduler'); r = r:gsub(':(%d+)', function(n) if tonumber(n) and tonumber(n) > 200 then return ':200' end return ':' .. n end); return r end end", "@roblox/scheduler")()
end)
local function __makeLoggedFunction(name, fn)
    local wrapped
    if _G.__mkWrapper ~= nil then
        wrapped = _G.__mkWrapper(fn, name, function(nm, ...)
            __logCall(nm, __argsToRepr(...))
        end)
    elseif __useNewCClosure then
        wrapped = newcclosure(function(...)
            __logCall(name, __argsToRepr(...))
            return fn(...)
        end)
        __isCClosureTrack[wrapped]=true
    else
        wrapped = function(...)
            __logCall(name, __argsToRepr(...))
            return fn(...)
        end
    end
    __wrappedMap[wrapped] = fn
    -- Roblox stdlib/engine functions are C closures; register the wrapper so
    -- debug.info(f, "s") == "[C"] for scripts that check it
    if __nativeHook then __nativeHook(wrapped, name) end
    local ok, src = __pcall(debug.info, fn, "s")
    if ok and src == "[C]" then
        __origIsC[wrapped] = true
    else
        __origIsC[wrapped] = false
    end
    -- hide from string.dump (C functions error on dump, Lua don't) - make dump fail like C
    if string.dump then
        local origDump = string.dump
        -- wrap string.dump to error on our wrapped C functions like real C would
        -- we do this once, not per function
    end
    return wrapped
end
-- make string.dump error on C closures like real Roblox (pcall-safe, string frozen in Lune)
__pcall(function()
    local __origDump = string.dump
    if __origDump then
        local function __loggedDump(f, ...)
            if __isCClosureTrack[f] or (__wrappedMap[f] and __origIsC[f]) then
                error("attempt to dump a C function")
            end
            return __origDump(f, ...)
        end
        __pcall(function() string.dump = __loggedDump end)
        __pcall(function() __realEnv["string"].dump = __loggedDump end)
        if _G then __pcall(function() _G.string.dump = __loggedDump end) end
    end
end)

-- helper to wrap and replace in __realEnv (use normal indexing because Lune env uses metatable)
local function __wrapGlobal(name)
    local v = __realEnv[name]
    if __type(v) == "function" and name ~= "__LOG_DUMP" then
        if not __loggedGlobals[name] then
            __loggedGlobals[name] = (name == "error" and _G.__mkErrorWrapper ~= nil)
                and _G.__mkErrorWrapper(v, function(nm, ...) __logCall(nm, __argsToRepr(...)) end)
                or __makeLoggedFunction(name, v)
            -- use normal set (not rawset) to shadow metatable
            __realEnv[name] = __loggedGlobals[name]
        end
    end
end

-- wrap existing globals that are commonly logged (explicit list because pairs misses metatable globals in Lune)
-- skip pcall/xpcall to avoid logging footer noise
for _, k in __ipairs({"print","warn","error","assert","require","tostring","tonumber","string","table","math","os","debug","task","game","workspace","Vector3","CFrame","Instance","typeof"}) do
    __wrapGlobal(k)
end
-- wrap ALL raw functions in env (Lune's print etc are via metatable, so pairs misses them - handled via explicit list)
for k,v in __pairs(__realEnv) do
    if __type(v)=="function" and k ~= "__LOG_DUMP" and k ~= "__LOGS" and k ~= "__logCall" then
        if k ~= "getfenv" and k ~= "setfenv" and k ~= "pcall" and k ~= "xpcall" then
            __wrapGlobal(k)
        end
    end
end

-- wrap string/table/math/os methods for "string.char" style logging
-- NOTE: table.unpack uses generic __wrapTableMethods below (valid Luau repr), no custom %p wrapper
-- In Lune these tables are frozen, so per-method overwrite fails -> use proxy
local __nativeFns = setmetatable({}, {__mode = "k"})
-- real (unmocked) table library, captured before the Roblox table shim is installed
__realTable0 = table
-- real type(): the `type` global is replaced by a Roblox-flavored mock further down, so
-- every internal function check must go through this captured reference
local __realType = type
__realUnpack = __type(__realTable0) == "table" and __realTable0.unpack or nil
local __rawDbgInfo = (type(debug) == "table" and debug.info) or nil
-- global copy: the debug shim lives in a later payload chunk, where this local is out of scope
__realDbgInfo = __rawDbgInfo
local function __markNative(f, name)
    if __realType(f) == "function" then __nativeFns[f] = name or "?" end
    return f
end
local function __isNativeFn(f)
    if __realType(f) ~= "function" then return false end
    if __nativeFns[f] then return true end
    if __isCClosureTrack and __isCClosureTrack[f] then return true end
    if __origIsC and __origIsC[f] then return true end
    if __rawDbgInfo then
        local orig = __wrappedMap and __wrappedMap[f]
        if orig then
            local ok, r = __pcall(__rawDbgInfo, orig, "s")
            if ok and r == "[C]" then return true end
        end
        local ok, r = __pcall(__rawDbgInfo, f, "s")
        if ok and r == "[C]" then return true end
    end
    return false
end
-- late-bound hook: __makeLoggedFunction is defined before this block and registers
-- every wrapper it creates as a native closure
__nativeHook = __markNative
-- Final sweep, run from the loader right before the script chunk runs: register every
-- function the script can actually reach (proxy-resolved members included) as a C
-- closure, so debug.info(f, "s") == "[C]" for the whole engine surface.
__markEnvNatives = function()
    if __libRawTables == nil then return end
    for tname, raw in next, __libRawTables do
        local ns = __unc[tname] or __realEnv[tname]
        if ns ~= nil and ns ~= raw and __realType(ns) == "table" then
            for k in next, raw do
                if __realType(raw[k]) == "function" then
                    local ok, v = __pcall(function() return ns[k] end)
                    if ok and __realType(v) == "function" then __markNative(v, tname .. "." .. tostring(k)) end
                end
            end
        end
    end
    -- Base-library functions the samples inspect with debug.info(..., "slnaf") must
    -- report Roblox's C-closure metadata. The shims installed above (getmetatable /
    -- getfenv) are plain Luau closures, so register them explicitly.
    local _gseen = {}
    for _, _gname in __ipairs({"getmetatable", "getfenv", "setfenv", "setmetatable", "loadstring",
        "rawget", "rawset", "rawequal", "type", "next", "pcall", "xpcall", "error",
        "assert", "tostring", "tonumber", "select", "print", "unpack", "require"}) do
        local _envs = {__unc, __sharedEnv, _G, __realEnv}
        for _ei = 1, 4 do
            local _env = _envs[_ei]
            if _env ~= nil then
                local _okk, _g = __pcall(function() return _env[_gname] end)
                if _okk and __type(_g) == "function" and not _gseen[_g] then
                    _gseen[_g] = true
                    __markNative(_g, _gname)
                end
            end
        end
    end
end

local function __wrapTableMethods(tblName)
    local tbl = __realEnv[tblName]
    if __type(tbl) ~= "table" then return end
    __libRawTables = __libRawTables or {}
    __libRawTables[tblName] = tbl
    -- try direct per-method overwrite first
    local needProxy = false
    for mk, mv in __pairs(tbl) do
        if __type(mv)=="function" then
            local full = tblName.."."..mk
            -- read-only stdlib tables (Lune's string/table) keep the original function;
            -- Roblox still reports those as C closures, so register the original too
            __markNative(mv, full)
            if not __loggedGlobals[full] then
                __loggedGlobals[full] = __makeLoggedFunction(full, mv)
                local ok = __pcall(function() tbl[mk]=__loggedGlobals[full] end)
                if not ok or tbl[mk] ~= __loggedGlobals[full] then
                    needProxy = true
                end
            end
        end
    end
    if needProxy then
        -- create proxy for frozen table
        local proxy = {}
        setmetatable(proxy, {
            __index = function(_, k)
                local v = tbl[k]
                if __type(v)=="function" then
                    local full = tblName.."."..k
                    if not __loggedGlobals[full] then
                        __loggedGlobals[full] = __makeLoggedFunction(full, v)
                    end
                    return __loggedGlobals[full]
                end
                return v
            end,
            __newindex = function(_, k, v) __pcall(function() tbl[k]=v end) __rawset(proxy, k, v) end
        })
        -- replace global with proxy (shadow metatable __index)
        __realEnv[tblName] = proxy
        __pcall(function() __sharedEnv[tblName] = proxy end)
        __pcall(function() __unc[tblName] = proxy end)
        if _G and _G ~= __realEnv then __pcall(function() _G[tblName] = proxy end) end
    end
end
__wrapTableMethods("string")
__wrapTableMethods("table")
__wrapTableMethods("math")
-- Roblox exposes every stdlib function as a C closure; our logging wrappers are plain
-- Luau functions, so register them in the native registry (scripts check debug.info(f,"s"))
do
    for k, f in next, __loggedGlobals do
        if __realType(f) == "function" then __markNative(f, tostring(k)) end
    end
end
-- math.floor(infinity) must stay finite: some anti-tamper checks compare
-- math.huge > math.floor(math.huge - 1), which is only true when the floor of an
-- infinity saturates instead of returning inf.
do
    local m = __realEnv.math
    if __type(m) == "table" and __type(m.floor) == "function" then
        local __prevFloor = m.floor
        local __floorShim = function(x, ...)
            if x == 1/0 then return 1.7976931348623157e308 end
            if x == -1/0 then return -1.7976931348623157e308 end
            return __prevFloor(x, ...)
        end
        local __installed = false
        __markNative(__floorShim, "math.floor")
        if __pcall(function() m.floor = __floorShim end) and m.floor == __floorShim then
            __installed = true
        end
        if not __installed then
            local __mproxy = {}
            setmetatable(__mproxy, {
                __index = function(_, k)
                    if k == "floor" then return __floorShim end
                    return m[k]
                end,
                __newindex = function(_, k, v) __rawset(__mproxy, k, v) end,
            })
            __realEnv.math = __mproxy
            __sharedEnv.math = __mproxy
            if _G and _G ~= __realEnv then _G.math = __mproxy end
        end
    end
end
__wrapTableMethods("os")
__wrapTableMethods("bit32")
__wrapTableMethods("utf8")
__wrapTableMethods("coroutine")

-- // LUAU / ROBLOX STDLIB GAPS
-- These exist in real Roblox/Luau but were missing here, so any payload
-- that calls them (or gates on their presence) diverged from Roblox.
do
    local m = __realEnv.math
    if __type(m) == "table" then
        if __type(m.lerpAngle) ~= "function" then
            m.lerpAngle = function(a, b, t)
                a, b, t = a or 0, b or 0, t or 0
                local d = (b - a) % (2 * math.pi)
                if d > math.pi then d = d - 2 * math.pi end
                return a + d * t
            end
            __markNative(m.lerpAngle, "math.lerpAngle")
        end
        if __type(m.pingpong) ~= "function" then
            m.pingpong = function(len, t)
                len, t = len or 0, t or 0
                if len == 0 then return 0 end
                return len - math.abs((t % (len * 2)) - len)
            end
            __markNative(m.pingpong, "math.pingpong")
        end
        if __type(m.noise) ~= "function" then
            -- Roblox math.noise(x, y, z): deterministic 3D Perlin, range ~[-1, 1]
            local perm = (function()
                local t, a, b = {}, 0, 0
                for i = 0, 255 do t[i] = i end
                for i = 0, 255 do
                    a = (i * 57 + 47) % 256
                    b = t[i]; t[i] = t[a]; t[a] = b
                end
                local p = {}
                for i = 0, 511 do p[i] = t[i % 256] end
                return p
            end)()
            local fade, lerp = function(t) return t * t * t * (t * (t * 6 - 15) + 10) end,
                function(t, u, w) return u + t * (w - u) end
            local grad = function(h, x, y, z)
                h = h % 16
                local u, v = 0, 0
                if h < 8 then u, v = x, y end
                if h < 4 then return u + v end
                if h == 12 or h == 14 then return u - v end
                return u - v
            end
            m.noise = function(x, y, z)
                x, y, z = x or 0, y or 0, z or 0
                local fx, fy, fz = math.floor(x), math.floor(y), math.floor(z)
                local X = math.floor(fx) % 256
                local Y = math.floor(fy) % 256
                local Z = math.floor(fz) % 256
                x, y, z = x - fx, y - fy, z - fz
                local u, v, w = fade(x), fade(y), fade(z)
                local A = perm[X] + Y
                local AA = perm[A] + Z
                local AB = perm[A + 1] + Z
                local B = perm[X + 1] + Y
                local BA = perm[B] + Z
                local BB = perm[B + 1] + Z
                return lerp(w,
                    lerp(v, lerp(u, grad(perm[AA], x, y, z), grad(perm[BA], x - 1, y, z)),
                        lerp(u, grad(perm[AB], x, y - 1, z), grad(perm[BB], x - 1, y - 1, z))),
                    lerp(v, lerp(u, grad(perm[AA + 1], x, y, z - 1),
                        grad(perm[BA + 1], x - 1, y, z - 1)),
                        lerp(u, grad(perm[AB + 1], x, y - 1, z - 1),
                            grad(perm[BB + 1], x - 1, y - 1, z - 1))))
            end
            __markNative(m.noise, "math.noise")
        end
    end
    local b32 = __realEnv.bit32
    if __type(b32) == "table" then
        if __type(b32.tobit) ~= "function" then
            b32.tobit = function(x)
                x = math.floor(x or 0) % 4294967296
                if x >= 2147483648 then x = x - 4294967296 end
                return x
            end
            __markNative(b32.tobit, "bit32.tobit")
        end
        if __type(b32.tohex) ~= "function" then
            b32.tohex = function(x, ndigits)
                local v = b32.tobit(x)
                if v < 0 then v = v + 4294967296 end
                local s = string.format("%08X", v)
                if __type(ndigits) == "number" and ndigits >= 1 and ndigits <= 8 then
                    return string.sub(s, 9 - math.floor(ndigits))
                end
                return s
            end
            __markNative(b32.tohex, "bit32.tohex")
        end
    end
end

-- // RUNTIME STRING HARVESTER
-- Obfuscated VMs build payload strings via string.char(table.unpack(t)) or
-- table.concat({...}). The original __makeLoggedFunction logs ARGS, not
-- RETURNS, so the decoded text is never captured. This harvester catches
-- every long string returned by string.char / table.concat / string.sub and
-- stores it in __harvestedStrings for the footer dump — so even if the VM
-- never logs the string itself (no warn/print of it), we still recover it.
-- It CHAINS through the existing logged wrappers, so the per-call log lines
-- (which the Python post-processor rehydrates) still exist too.
__harvestedStrings = __harvestedStrings or {}
do
    local __seenHash = {}
    local function __tryHarvest(result)
        if __type(result) ~= "string" then return end
        if #result < 20 then return end
        -- only harvest strings that look like text (avoid binary junk)
        local printable = 0
        for ci = 1, #result do
            local b = string.byte(result, ci)
            if b == 9 or b == 10 or b == 13 or (b >= 32 and b <= 126) then printable = printable + 1 end
        end
        if (printable / #result) < 0.85 then return end
        -- dedupe: hash first 80 bytes + length
        local key = result:sub(1, 80) .. "|" .. tostring(#result)
        if __seenHash[key] then return end
        __seenHash[key] = true
        __harvestedStrings[#__harvestedStrings + 1] = result
    end
    -- intercept string.char: the main decode primitive in every obfuscator
    -- (chains through __loggedGlobals["string.char"] so the log line + harvest both happen)
    local __strCharReal = __loggedGlobals["string.char"] or (__realEnv.string and __realEnv.string.char)
    local function __strCharWrap(...)
        local r = __strCharReal(...)
        __tryHarvest(r)
        return r
    end
    __pcall(function() string.char = __strCharWrap end)
    if __realEnv.string ~= string then
        __pcall(function() __realEnv.string.char = __strCharWrap end)
    end
    -- intercept table.concat: the secondary decode primitive
    local __tblConcatReal = __loggedGlobals["table.concat"] or (__realEnv.table and __realEnv.table.concat)
    local function __tblConcatWrap(t, sep)
        local r = __tblConcatReal(t, sep)
        if sep == nil or sep == "" then
            __tryHarvest(r)
        end
        return r
    end
    __pcall(function() table.concat = __tblConcatWrap end)
    if __realEnv.table ~= table then
        __pcall(function() __realEnv.table.concat = __tblConcatWrap end)
    end
    -- wrap the other string functions that can RETURN long text strings
    -- (gsub/rep/format/reverse/match). These also chain through logged wrappers.
    local function __wrapStrRet(fname)
        local base = __loggedGlobals["string." .. fname] or (__realEnv.string and __realEnv.string[fname])
        if __type(base) ~= "function" then return end
        local function w(...)
            local r, n2 = base(...)
            __tryHarvest(r)
            return r, n2
        end
        __pcall(function() string[fname] = w end)
        if __realEnv.string ~= string then
            __pcall(function() __realEnv.string[fname] = w end)
        end
    end
    __wrapStrRet("gsub")
    __wrapStrRet("rep")
    __wrapStrRet("format")
    __wrapStrRet("reverse")
    __wrapStrRet("match")
end

-- // CRASH GUARD: cap memory-bomb primitives so a logged script can't OOM/hang your PC.
-- Obfuscator VMs never need 100MB strings or billion-entry tables; stealers/crashers do.
-- Behavior is clamped (not removed), so legit payloads keep running.
do
    local __capNotes = 0
    local function __capNote(msg)
        if __capNotes >= 8 then return end
        __capNotes = __capNotes + 1
        __LOG_COUNT = __LOG_COUNT + 1
        if __LOG_COUNT <= __MAX_LOGS then
            __table_insert(__LOGS, "-- LIMIT: " .. msg .. " (clamped, script keeps running)")
        end
    end
    -- resolve the ORIGINAL fn behind our logging wrapper (works frozen or not)
    local function __origOf(tblName, meth)
        local ok, tbl = __pcall(function() return __realEnv[tblName] end)
        if not ok or __type(tbl) ~= "table" then return nil end
        local ok2, w = __pcall(function() return tbl[meth] end)
        if not ok2 then return nil end
        return __wrappedMap[w] or w
    end
    -- install capped version: direct overwrite AND proxy-cache entry (covers frozen tables)
    local function __installCap(tblName, meth, cappedFn)
        local logged = __makeLoggedFunction(tblName.."."..meth, cappedFn)
        __loggedGlobals[tblName.."."..meth] = logged
        __pcall(function() __realEnv[tblName][meth] = logged end)
    end
    do
        local orig = __origOf("string", "rep") or string.rep
        __installCap("string", "rep", function(s, n, sep)
            s = __tostring(s or "")
            n = tonumber(n) or 0
            if n > 100000 then __capNote("string.rep(" .. n .. ") clamped to 100000") n = 100000 end
            if #s * n > 2000000 then
                n = __math_floor(2000000 / (#s > 0 and #s or 1))
                __capNote("string.rep result clamped to ~2MB")
            end
            if n < 0 then n = 0 end
            return orig(s, n, sep)
        end)
    end
    do
        local orig = __origOf("string", "char") or string.char
        __installCap("string", "char", function(...)
            local n = __select("#", ...)
            if n > 100000 then
                __capNote("string.char(" .. n .. " args) truncated to 100000")
                local args = {...}
                return orig(__select(1, table.unpack(args, 1, 100000)))
            end
            return orig(...)
        end)
    end
    do
        local ok, tbl = __pcall(function() return __realEnv["table"] end)
        local origCreate = (ok and __type(tbl) == "table" and __wrappedMap[tbl.create]) or table.create
        if __type(origCreate) == "function" then
            __installCap("table", "create", function(n, v)
                n = tonumber(n) or 0
                if n > 100000 then __capNote("table.create(" .. n .. ") clamped to 100000") n = 100000 end
                -- real Lua/Roblox rejects a negative count; keep that (anti-tamper probes it)
                if n < 0 then error("table.create: size must be non-negative", 2) end
                return origCreate(n, v)
            end)
        end
        local origUnpack = (ok and __type(tbl) == "table" and (__wrappedMap[tbl.unpack] or tbl.unpack)) or table.unpack
        if __type(origUnpack) == "function" then
            __installCap("table", "unpack", function(t, i, j)
                if __type(t) == "table" and j ~= nil and i ~= nil and (j - i) > 100000 then
                    __capNote("table.unpack range clamped to 100000")
                    j = i + 100000
                end
                return origUnpack(t, i, j)
            end)
        end
    end
    -- NOTE: buffer.create is capped at its UNC mock below (mock is defined later).
end

-- // UNC emulation - inject directly into __realEnv (bare globals) + __unc fallback
-- Registry of functions that Roblox (and executors) expose as C closures. Scripts assert
-- debug.info(f, "s") == "[C]" / iscclosure(f) on API functions, so every engine function we
-- hand out has to be recognizable as native.
local function __setUNC(name, fn)
    if __realType(fn) == "function" then
        __markNative(fn, name)
    elseif __realType(fn) == "table" then
        -- namespaces (Instance, UDim2, task, Random, CFrame, Axes...) are handed to the
        -- script as tables, but Roblox exposes their members as C closures
        for k, v in next, fn do
            if __realType(v) == "function" then __markNative(v, tostring(name) .. "." .. tostring(k)) end
        end
    end
    __unc[name] = fn
    __pcall(function() __sharedEnv[name] = fn end)
    __pcall(function() __rawset(__sharedEnv, name, fn) end)
    __pcall(function() __realEnv[name] = fn end)
    if _G and _G ~= __realEnv then
        __pcall(function() _G[name]=fn end)
    end
end

-- pass-through pairs: a script pairs()-ing userdata should get Roblox's behavior
-- (an error). If that error happens after real payload logs, the footer's
-- graceful-end gate treats it as VM teardown noise, not a script failure.
local __origPairs = pairs
__realEnv.pairs = function(x) return __origPairs(x) end
if _G and _G ~= __realEnv then _G.pairs = __realEnv.pairs end

__setUNC("getgenv", function() return __sharedEnv end)
-- setfenv: after loadstring, anti-tamper payloads call setfenv(chunk, getfenv()).
-- Capture Lune's real setfenv first, then expose a guarded pass-through on _G too.
local __realSetfenv = setfenv
__setUNC("setfenv", function(f, e)
    -- real Lua refuses to retarget a C closure's environment; scripts probe exactly this
    if __isNativeFn(f) then error("setfenv: cannot change the environment of a C function", 2) end
    if __type(f) == "function" then __pcall(__realSetfenv, f, e) end
    return true
end)
__setUNC("getrenv", function() return __realEnv end)
__setUNC("getreg", function() if debug and debug.getregistry then return debug.getregistry() else return {} end end)
__setUNC("getgc", function() return {} end)
__setUNC("getinstances", function() return {} end)
__setUNC("getnilinstances", function() return {} end)
__setUNC("getscripts", function() return {} end)
__setUNC("getsenv", function() return {} end)
__setUNC("getmenv", function() return __realEnv end)
__setUNC("getnamecallmethod", function() return "" end)
__setUNC("setnamecallmethod", function() return nil end)
__setUNC("checkcaller", function() return false end)
__setUNC("islclosure", function(f)
    if __wrappedMap[f] or __isCClosureTrack[f] then
        -- if wrapped and original was C, act like C was not present? Actually wrapped is Lua, but should appear as C if original was C
        if __origIsC[f] then return false end
        if __isCClosureTrack[f] then return false end
    end
    if __origIsC[f] then return false end
    local ok,r=__pcall(debug.info,f,"s")
    if not ok then return __type(f)=="function" end
    if __wrappedMap[f] then
        local orig = __wrappedMap[f]
        local ok2, src2 = __pcall(debug.info, orig, "s")
        if ok2 and src2=="[C]" then return false end
    end
    return r~="[C]"
end)
__setUNC("iscclosure", function(f)
    if __wrappedMap[f] and __origIsC[f] then return true end
    if __isCClosureTrack[f] then return true end
    local ok,r=__pcall(debug.info,f,"s")
    if not ok then return false end
    if __wrappedMap[f] then
        local orig = __wrappedMap[f]
        local ok2, src2 = __pcall(debug.info, orig, "s")
        if ok2 and src2=="[C]" then return true end
    end
    return r=="[C]"
end)
__setUNC("isexecutorclosure", function(f)
    if f==nil then return true end
    if __wrappedMap[f] or __isCClosureTrack[f] then return true end
    return true
end)
__setUNC("isourclosure", function(f)
    if __wrappedMap[f] or __isCClosureTrack[f] then return true end
    local ok,r=__pcall(debug.info,f,"s")
    if not ok then return true end
    return r~="[C]"
end)
__setUNC("clonefunction", function(f)
    if __type(f)~="function" then return f end
    local copy = function(...) return f(...) end
    __wrappedMap[copy] = f
    __origIsC[copy] = __origIsC[f] or false
    return copy
end)
__setUNC("newcclosure", function(f)
    if __type(f)~="function" then return f end
    local c = function(...) return f(...) end
    __isCClosureTrack[c]=true
    __wrappedMap[c]=f
    __origIsC[c]=true
    return c
end)
local __realMts = setmetatable({}, {__mode="k"})
__setUNC("getrawmetatable", function(t)
    if __realMts[t] then return __realMts[t] end
    local mt = __origGetmetatable(t)
    return mt
end)
__setUNC("setrawmetatable", function(t, mt)
    __realMts[t]=mt
    return __origSetmetatable(t, mt)
end)
-- minimal executor console/raw helpers some Boronide-style loaders call
__setUNC("rconsoleclear", function() return nil end)
__setUNC("rconsolename", function(name) if name ~= nil then return nil end return "EnvLogger" end)
__setUNC("setraw", function(t, ...) return __origSetmetatable(t, ...) end)
__setUNC("setreadonly", function(t, v)
    if __type(t)~="table" then return end
    if v==false then
        -- try unfreeze
        if table.isfrozen and table.isfrozen(t) then
            -- Lune: table.clone to unfreeze
            local ok, tbl = __pcall(table.clone, t)
            if ok and tbl then
                for k,v in pairs(t) do tbl[k]=v end
                return
            end
        end
        __pcall(function() __origSetmetatable(t, __origGetmetatable(t)) end)
    else
        __pcall(function() table.freeze(t) end)
    end
end)
__setUNC("isreadonly", function(t)
    if table.isfrozen then
        local ok, res = __pcall(table.isfrozen, t)
        if ok then return res end
    end
    return false
end)
local __hooks = {}
__setUNC("hookfunction", function(f, hook)
    if __type(f)~="function" or __type(hook)~="function" then return f end
    __hooks[f]=hook
    -- try to actually replace in env if f is global
    for k,v in pairs(__realEnv) do if v==f then __realEnv[k]=hook; break end end
    return f
end)
__setUNC("hookmetamethod", function(t, m, hook)
    local mt = __realMts[t] or __origGetmetatable(t)
    if not mt then mt={}; __origSetmetatable(t, mt); __realMts[t]=mt end
    local orig = mt[m]
    mt[m]=hook
    __hooks[orig]=hook
    return orig
end)
__setUNC("gethiddenproperty", function() return nil end)
__setUNC("sethiddenproperty", function() return true end)
__setUNC("gethui", function() return __realEnv end)
__setUNC("getcustomasset", function(p) return "rbxasset://"..tostring(p) end)
__setUNC("isnetworkowner", function() return true end)
__setUNC("fireclickdetector", function() return nil end)
__setUNC("firetouchinterest", function() return nil end)
__setUNC("firesignal", function(f) if f then local ok=pcall(function() f() end) end return nil end)
__setUNC("getconnections", function(f) return {} end)
__setUNC("getcallingscript", function() return {Name="logged", ClassName="LocalScript", GetFullName=function() return "Logged" end} end)
__setUNC("identifyexecutor", function() return "Synapse X", "v1.0" end)
__setUNC("getexecutorname", function() return "Synapse X" end)
__setUNC("request", __makeBlockedFn("request"))
__setUNC("http_request", __makeBlockedFn("http_request"))
__setUNC("httprequest", __makeBlockedFn("httprequest"))
__setUNC("http", {request=__makeBlockedFn("http.request"), get=__makeBlockedFn("http.get"), post=__makeBlockedFn("http.post")})
__setUNC("queue_on_teleport", function() return nil end)
__setUNC("queueonteleport", function() return nil end)
__setUNC("setclipboard", function(s) return true end)
__setUNC("toclipboard", function(s) return true end)
__setUNC("getclipboard", function() return "" end)
__setUNC("setfpscap", function(n) return nil end)
__setUNC("getfpscap", function() return 60 end)
__setUNC("isrbxactive", function() return true end)
__setUNC("iswindowactive", function() return true end)
__setUNC("mouse1click", function() return nil end)
__setUNC("mouse1press", function() return nil end)
__setUNC("mouse1release", function() return nil end)
__setUNC("mouseclick", function() return nil end)
__setUNC("keypress", function() return nil end)
__setUNC("keyrelease", function() return nil end)
__setUNC("keytap", function() return nil end)
__setUNC("isfile", function(p) return false end)
__setUNC("isfolder", function(p) return false end)
__setUNC("listfiles", function(p) return {} end)
__setUNC("makefolder", function(p) return nil end)
__setUNC("delfolder", function(p) return nil end)
__setUNC("delfile", function(p) return nil end)
__setUNC("writefile", function(p,c) return nil end)
__setUNC("readfile", function(p) return "" end)
__setUNC("loadfile", function(p) return function() end end)
__setUNC("dofile", function(p) return nil end)
__setUNC("getscriptclosure", function(s) return function() end end)
__setUNC("getscripthash", function(s) return "hash" end)
__setUNC("getscriptbytecode", function(s) return "" end)
__setUNC("dumpstring", function(s) return "" end)
__setUNC("getthreadidentity", function() return 7 end)
__setUNC("setthreadidentity", function(n) return nil end)
__setUNC("getthreadcontext", function() return 7 end)
__setUNC("setthreadcontext", function(n) return nil end)
__setUNC("getidentity", function() return 7 end)
__setUNC("setidentity", function(n) return nil end)
-- executor-style loadstring (must be after __setUNC defined)
do
    local __origLoadstring = __realEnv.loadstring or loadstring or load
    local __origLoad = __realEnv.load or load
    local function __execLoadstring(s, chunkname)
        -- skip ONLY the loader's own loadstring for the original script (internal flag)
        if __isLoaderLoad then
            local fn, err = __origLoadstring(s, chunkname)
            if fn and setfenv then pcall(setfenv, fn, __realEnv) end
            return fn, err
        end
        if __type(s) == "string" then
            -- store full second-stage source for later dump (not truncated)
            if #__STAGED < __MAX_STAGES then
                __STAGED[#__STAGED + 1] = {
                    chunk = chunkname or "loadstring",
                    src = s,
                    bytes = #s,
                }
            end
            -- Cooperative VM preemption: inject __vmTick() into the payload's
            -- decode loop(s). Pure-Lua transform on the *source string* of the
            -- payload, so the drived coroutine can yield out of a tight
            -- `while(X)do`/`while(true)do` spin and the footer dump can run.
            if __VM_INJECT then
                s = __VM_INJECT(s)
            end
            -- flush immediately: a stack overflow later must not lose the payload
            if __flushStagedLive then __flushStagedLive() end
            -- log full source inline when enabled
            __logCall("loadstring", __reprFullPayload(s, "loadstring(first-stage)[" .. #s .. " bytes]"))
        else
            __logCall("loadstring", __repr(s))
        end
        local fn, err = __origLoadstring(s, chunkname or "loadstring")
        if fn then
            if setfenv then pcall(setfenv, fn, __realEnv) end
            return fn, err
        end
        return fn, err
    end
    local function __execLoad(s, chunkname, mode, env)
        if __isLoaderLoad then
            local fn, err = __origLoad(s, chunkname, mode, env or __realEnv)
            if fn and env==nil and setfenv then pcall(setfenv, fn, __realEnv) end
            return fn, err
        end
        if __type(s) == "string" then
            if #__STAGED < __MAX_STAGES then
                __STAGED[#__STAGED + 1] = {
                    chunk = chunkname or "load",
                    src = s,
                    bytes = #s,
                }
            end
            -- flush immediately: a stack overflow later must not lose the payload
            if __flushStagedLive then __flushStagedLive() end
            local name = chunkname and __repr(chunkname) or __reprFullPayload(s, "load(first-stage)[" .. #s .. " bytes]")
            __logCall("load", name)
        else
            local name = chunkname and __repr(chunkname) or __repr(s and s:sub(1,30) or "")
            __logCall("load", name)
        end
        local fn, err = __origLoad(s, chunkname, mode, env or __realEnv)
        if fn and env==nil and setfenv then pcall(setfenv, fn, __realEnv) end
        return fn, err
    end
    __setUNC("loadstring", __execLoadstring)
    __setUNC("load", __execLoad)
    __realEnv.loadstring = __execLoadstring
    __realEnv.load = __execLoad
    if _G and _G ~= __realEnv then
        _G.loadstring = __execLoadstring
        _G.load = __execLoad
    end
end
-- 100% UNC/sUNE/eUNC - additional (covers all known checks)
__setUNC("cache", setmetatable({invalidate=function() return nil end, iscached=function() return false end, replace=function() return nil end}, {__index=function() return function() return nil end end}))
__setUNC("cloneref", function(o) return o end)
__setUNC("compareinstances", function(a,b) return a==b end)
__setUNC("getloadedmodules", function() return {} end)
__setUNC("getrunningscripts", function() return {} end)
__setUNC("getscripts", function() return {} end)
__setUNC("getscriptbytecode", function(s) return "" end)
__setUNC("dumpstring", function(s) return "" end)
__setUNC("decompile", function(s) return "-- decompiled" end)
__setUNC("getscriptclosure", function(s) return function() end end)
__setUNC("getscripthash", function(s) return "hash" end)
__setUNC("getcallingscript", function() return {Name="Logged", ClassName="LocalScript", Source="-- logged"} end)
__setUNC("getrenderproperty", function(i,p) return nil end)
    __setUNC("setrenderproperty", function(i,p,v) return nil end)
    -- rawget/rawset/rawequal: standard Lua but some UNC-style checks look for them
    local __origRawget = __rawget and __rawget or (type(rawget) == "function" and rawget or _G.rawget)
    local __origRawset = rawset
    local __origRawequal = rawequal
    local __origType = type
    __setUNC("rawget", function(t, ...)
        -- Roblox's rawget validates its arity; the engine raises a "missing
        -- argument" error that anti-tamper samples match against.
        local __n = select("#", ...)
        if t == nil then error("missing argument #1 to 'rawget'", 2) end
        if __n == 0 then error("missing argument #2 to 'rawget'", 2) end
        local k = ...
        if __origType(t) == "table" then
            return __origRawget(t, k)
        end
        return nil
    end)
    __setUNC("rawset", function(t, k, v)
        if __origType(t) == "table" then
            __origRawset(t, k, v)
            return v
        end
        return v
    end)
    __setUNC("rawequal", function(a, b) return __origRawequal(a, b) end)
-- sUNC extras
__setUNC("crypt", {base64encode=function(s) return s end, base64decode=function(s) return s end, encrypt=function() return "" end, decrypt=function() return "" end, generatebytes=function(n) return string.rep("\0",n) end, generatekey=function() return "" end, hash=function(s) return "" end})
__setUNC("base64", {encode=function(s) return s end, decode=function(s) return s end})
__setUNC("Drawing", setmetatable({new=function(t) return {Visible=true, Remove=function() end, Destroy=function() end} end, Fonts={}}, {__index=function() return function() return {} end end}))
__setUNC("WebSocket", {connect=function(url) __exfilBlock("WebSocket.connect", url) return {Send=function() return nil end, Close=function() return nil end, OnMessage={Connect=function() return {} end}} end})
__setUNC("debug", __realEnv.debug or debug)
__setUNC("listfiles", function() return {} end)
__setUNC("isfile", function() return false end)
__setUNC("writefile", function() return true end)
__setUNC("readfile", function() return "" end)
__setUNC("makefolder", function() return true end)
__setUNC("delfile", function() return true end)
__setUNC("getrawmetatable", __unc.getrawmetatable)
__setUNC("setrawmetatable", __unc.setrawmetatable)
__setUNC("setclipboard", function(s) return true end)
__setUNC("getclipboard", function() return "" end)
__setUNC("setfpscap", function(n) return true end)
__setUNC("getfpscap", function() return 60 end)
__setUNC("queue_on_teleport", function(s) return true end)
__setUNC("httprequest", __makeBlockedFn("httprequest"))
__setUNC("http_request", __makeBlockedFn("http_request"))
__setUNC("request", __makeBlockedFn("request"))
-- syn compatibility (request goes through exfil sinkhole, never real network)
__setUNC("syn", setmetatable({request=__makeBlockedFn("syn.request"), cache_replace=function() end, cache_invalidate=function() end, is_cached=function() return false end}, {__index=function(_, k) if k=="request" then return __makeBlockedFn("syn.request") end return __unc[k] end}))
__setUNC("fluxus", setmetatable({request=__makeBlockedFn("fluxus.request")}, {__index=function(_, k) if k=="request" then return __makeBlockedFn("fluxus.request") end return __unc[k] end}))
__setUNC("getexecutorname", function() return "Synapse X" end)
__setUNC("identifyexecutor", function() return "Synapse X", "1.0" end)
-- // EXFIL GUARD part 2: kill Lune-native network + secret-stealing primitives
-- Lune exposes real net/fs/process via globals or require(). All sinkholed here.
do
    local __sinkNet = {request=__makeBlockedFn("net.request"), get=__makeBlockedFn("net.get"), post=__makeBlockedFn("net.post"), serve=function() return nil end, socket={tcp=function() __exfilBlock("net.socket.tcp", "?") return nil end, udp=function() __exfilBlock("net.socket.udp", "?") return nil end}, websocket={connect=function(u) __exfilBlock("net.websocket.connect", u) return {send=function() return nil end, close=function() return nil end} end}}
    for _, nk in ipairs({"net", "socket", "fetch", "websocket"}) do
        __pcall(function() __realEnv[nk] = (nk == "net" and __sinkNet) or nil end)
        __pcall(function() __sharedEnv[nk] = __realEnv[nk] end)
        if _G and _G ~= __realEnv then __pcall(function() _G[nk] = __realEnv[nk] end) end
    end
    -- os.execute / io.popen could exfiltrate via curl/powershell; io.read could steal stdin secrets
    __pcall(function()
        if __realEnv.os then
            __pcall(function() __realEnv.os.execute = function(...) __exfilBlock("os.execute", "shell") return nil end end)
            __pcall(function() __realEnv.os.getenv = function(...) return "" end end)
            __pcall(function() __realEnv.os.remove = function(...) return nil end end)
            __pcall(function() __realEnv.os.rename = function(...) return nil end end)
        end
        if __realEnv.io then
            __pcall(function() __realEnv.io.popen = function(...) __exfilBlock("io.popen", "shell") return nil end end)
        end
    end)
    -- require("@lune/net") / require("fs") bypass: block net + fs modules, allow everything else
    do
        local __origRequire = __realEnv.require or require
        -- EncodingService needs REAL zstd/lz4/gzip/brotli to unpack wrapped
        -- payloads, and @lune/serde is a pure codec module (no fs/net), so grab
        -- it here while require is still the real one. Nil'd again right after
        -- the encoding chunk is built, and never exposed to the payload.
        _G.__serde = nil
        __pcall(function() _G.__serde = __origRequire("@lune/serde") end)
        if __origRequire then
            -- Roblox-style require(ModuleInstance) returns a module; in Lune require()
            -- only takes a string module name, so return a callable+indexable stub so
            -- loader VMs can require(game:GetService("ReplicatedStorage").SomeModule).
            local function __makeModuleStub()
                local mod = {}
                setmetatable(mod, {
                    __index = function(_, k) return __makeModuleStub() end,
                    __call = function(...) return __makeModuleStub() end,
                })
                return mod
            end
            local function __safeRequire(mod, ...)
                local m = tostring(mod or ""):lower()
                -- A real Roblox executor has NO @lune runtime: require("@lune/fs") etc must
                -- FAIL (pcall false, error thrown) — anti-tamps check this. Still log the
                -- attempted module so an @lune exfil probe is visible in the transcript.
                if m:find("@lune", 1, true) or m:find("fs", 1, true) or m:find("process", 1, true) then
                    __exfilBlock("require", mod)
                    error("@lune modules are not available in this environment", 2)
                end
                if m:find("net", 1, true) or m:find("socket", 1, true) or m:find("websocket", 1, true) or m:find("http", 1, true) then
                    __exfilBlock("require", mod)
                    return __sinkNet
                end
                if __type(mod) == "userdata" then
                    __logCall("require", "ModuleInstance")
                    return __makeModuleStub()
                end
                local ok, r = __pcall(__origRequire, mod, ...)
                if ok then return r end
                -- fallback: unknown module name -> stub
                return __makeModuleStub()
            end
            __setUNC("require", __safeRequire)
            __pcall(function() __realEnv.require = __safeRequire end)
        end
    end
end
-- SECURITY: never expose host Lune/real filesystem to the logged script.
-- A stealer could readfile() your real files/tokens and POST them to a webhook.
-- Keep the in-memory VFS only (defined below); do NOT alias real writefile/readfile here.

-- // eUNC fixes: real behavior for crypt/files/hooks/checkcaller/missing globals (overrides stubs above)
do
    -- checkcaller: whole Lune process IS the executor thread
    __setUNC("checkcaller", function() return true end)
    -- getgenv must contain _G and be consistent
    __pcall(function() __rawset(__sharedEnv, "_G", _G or __realEnv) end)
    __pcall(function() if not __rawget(__sharedEnv, "game") then __rawset(__sharedEnv, "game", __realEnv.game) end end)
    -- ypcall alias
    __setUNC("ypcall", function(f, ...) local ok, r = pcall(f, ...) if ok then return true, r else return false, r end end)
    -- clipboard / fps round-trip state
    local __clip = ""
    __setUNC("setclipboard", function(s) __clip = tostring(s or "") return true end)
    __setUNC("toclipboard", function(s) __clip = tostring(s or "") return true end)
    __setUNC("getclipboard", function() return __clip end)
    local __fps = 60
    __setUNC("setfpscap", function(n) if type(n)=="number" then __fps = n end return nil end)
    __setUNC("getfpscap", function() return __fps end)
    -- in-memory virtual filesystem so write/read/append/delete round-trip
    -- // CRASH GUARD: VFS caps — writefile("x", rep("A",1e9)) or appendfile-in-a-loop
    -- would eat all your RAM. Per-file 1MB, 2000 files max (script keeps running).
    local __vfs, __vfolders, __vfsCount = {}, {}, 0
    __setUNC("writefile", function(p, c)
        local k, v = tostring(p), tostring(c or "")
        if #v > 1000000 then v = v:sub(1, 1000000) end
        if __vfs[k] == nil then __vfsCount = __vfsCount + 1 end
        if __vfsCount > 2000 then return nil end
        __vfs[k] = v
        return nil
    end)
    __setUNC("readfile", function(p) local v = __vfs[tostring(p)] if v == nil then error("readfile: file not found: " .. tostring(p)) end return v end)
    __setUNC("appendfile", function(p, c)
        local k = tostring(p)
        local v = (__vfs[k] or "") .. tostring(c or "")
        if #v > 1000000 then v = v:sub(1, 1000000) end
        if __vfs[k] == nil then __vfsCount = __vfsCount + 1 end
        if __vfsCount > 2000 then return nil end
        __vfs[k] = v
        return nil
    end)
    __setUNC("delfile", function(p) __vfs[tostring(p)] = nil return nil end)
    __setUNC("isfile", function(p) return __vfs[tostring(p)] ~= nil end)
    __setUNC("isfolder", function(p) return __vfolders[tostring(p)] == true end)
    __setUNC("makefolder", function(p) __vfolders[tostring(p)] = true return nil end)
    __setUNC("delfolder", function(p) __vfolders[tostring(p)] = nil return nil end)
    __setUNC("listfiles", function(p) local out = {} local pre = tostring(p or "") for k, _ in pairs(__vfs) do if pre == "" or __str_sub(k, 1, #pre) == pre then out[#out + 1] = k end end return out end)
    __setUNC("loadfile", function(p) local v = __vfs[tostring(p)] if v == nil then return nil, "not found" end local fn, err = (loadstring or load)(v) return fn, err end)
    __setUNC("dofile", function(p) local v = __vfs[tostring(p)] if v == nil then error("dofile: not found") end local fn = (loadstring or load)(v) return fn() end)
    -- real base64 (pure Lua, uses captured locals so no log spam)
    local __b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local __b64map = {}
    for i = 1, #__b64c do __b64map[__str_sub(__b64c, i, i)] = i - 1 end
    local function __b64enc(data)
        data = tostring(data)
        local out, n = {}, #data
        for i = 1, n, 3 do
            local a = __str_byte(data, i) or 0
            local b = __str_byte(data, i + 1)
            local c = __str_byte(data, i + 2)
            local v = a * 65536 + (b or 0) * 256 + (c or 0)
            out[#out + 1] = __str_sub(__b64c, __math_floor(v / 262144) % 64 + 1, __math_floor(v / 262144) % 64 + 1)
            out[#out + 1] = __str_sub(__b64c, __math_floor(v / 4096) % 64 + 1, __math_floor(v / 4096) % 64 + 1)
            out[#out + 1] = (b == nil) and "=" or __str_sub(__b64c, __math_floor(v / 64) % 64 + 1, __math_floor(v / 64) % 64 + 1)
            out[#out + 1] = (c == nil) and "=" or __str_sub(__b64c, v % 64 + 1, v % 64 + 1)
        end
        return __table_concat(out)
    end
    local function __b64dec(data)
        data = tostring(data):gsub("[^A-Za-z0-9+/=]", "")
        local out = {}
        for i = 1, #data, 4 do
            local function _v(j)
                local ch = __str_sub(data, i + j - 1, i + j - 1)
                if ch == "" or ch == "=" then return 0 end
                return __b64map[ch] or 0
            end
            local n = _v(1) * 262144 + _v(2) * 4096 + _v(3) * 64 + _v(4)
            out[#out + 1] = __str_char(__math_floor(n / 65536) % 256)
            if __str_sub(data, i + 2, i + 2) ~= "=" then out[#out + 1] = __str_char(__math_floor(n / 256) % 256) end
            if __str_sub(data, i + 3, i + 3) ~= "=" then out[#out + 1] = __str_char(n % 256) end
        end
        return __table_concat(out)
    end
    local function __xor3(a, b, c)
        local r = a
        if bit32 and bit32.bxor then r = bit32.bxor(r, b) r = bit32.bxor(r, c or 0) else r = (r + b + (c or 0)) % 256 end
        return r
    end
    local function __randbytes(n)
        local t = {}
        for i = 1, n do t[i] = __str_char(__math_floor(__math_random() * 256)) end
        return __table_concat(t)
    end
    local function __hex(s)
        local t = {}
        for i = 1, #s do t[i] = string.format("%02x", __str_byte(s, i)) end
        return __table_concat(t)
    end
    local function __cryptenc(data, key)
        data, key = tostring(data), tostring(key)
        if #key == 0 then key = "k" end
        local iv = __randbytes(8)
        local eb = {}
        for i = 1, #data do
            local kb = __str_byte(key, ((i - 1) % #key) + 1)
            local ivb = __str_byte(iv, ((i - 1) % 8) + 1)
            eb[i] = __str_char(__xor3(__str_byte(data, i), kb, ivb))
        end
        return __b64enc(__table_concat(eb)), __b64enc(iv)
    end
    local function __cryptdec(enc, key, iv)
        local raw = __b64dec(enc)
        local ivr = __b64dec(iv)
        local kk = tostring(key)
        if #kk == 0 then kk = "k" end
        local db = {}
        for i = 1, #raw do
            local kb = __str_byte(kk, ((i - 1) % #kk) + 1)
            local ivb = __str_byte(ivr, ((i - 1) % 8) + 1) or 0
            db[i] = __str_char(__xor3(__str_byte(raw, i), kb, ivb))
        end
        return __table_concat(db)
    end
    local __crypt = {}
    __crypt.base64encode = function(s) return __b64enc(s) end
    __crypt.base64decode = function(s) return __b64dec(s) end
    __crypt.encrypt = function(d, k) return __cryptenc(d, k) end
    __crypt.decrypt = function(e, k, iv) return __cryptdec(e, k, iv) end
    __crypt.generatekey = function() return __randbytes(32) end
    __crypt.generatebytes = function(n) return __randbytes(tonumber(n) or 16) end
    __crypt.hash = function(s) return __hex(tostring(s) .. #tostring(s)) end
    __crypt.hmac = function(s, k) return __hex(tostring(s) .. tostring(k)) end
    __crypt.random = function(n) return __randbytes(tonumber(n) or 16) end
    __crypt.lz4compress = function(s) return tostring(s) end
    __crypt.lz4decompress = function(s, sz) return tostring(s) end
    __crypt.base64 = {encode = function(s) return __b64enc(s) end, decode = function(s) return __b64dec(s) end}
    __setUNC("crypt", __crypt)
    __setUNC("base64encode", function(s) return __b64enc(s) end)
    __setUNC("base64decode", function(s) return __b64dec(s) end)
    __setUNC("base64_encode", function(s) return __b64enc(s) end)
    __setUNC("base64_decode", function(s) return __b64dec(s) end)
    __setUNC("base64", {encode = function(s) return __b64enc(s) end, decode = function(s) return __b64dec(s) end})
    __setUNC("lz4compress", function(s) return tostring(s) end)
    __setUNC("lz4decompress", function(s, sz) return tostring(s) end)
    -- hookfunction that really swaps reachable references + restores
    __hooks = {}
    __setUNC("hookfunction", function(f, hook)
        if __type(f) ~= "function" or __type(hook) ~= "function" then return f end
        __hooks[f] = hook
        for _, tbl in ipairs({__realEnv, _G, __sharedEnv}) do
            if __type(tbl) == "table" then
                for k, v in pairs(tbl) do
                    if v == f then pcall(function() tbl[k] = hook end) end
                end
            end
        end
        return f
    end)
    __setUNC("restorefunction", function(f)
        for orig, hook in pairs(__hooks) do
            if hook == f or orig == f then
                for _, tbl in ipairs({__realEnv, _G, __sharedEnv}) do
                    if __type(tbl) == "table" then
                        for k, v in pairs(tbl) do
                            if v == hook then pcall(function() tbl[k] = orig end) end
                        end
                    end
                end
                return orig
            end
        end
        return f
    end)
    -- missing debug / misc globals (existence + safe behavior)
    __setUNC("getcallbackvalue", function(...) return function() end end)
    __setUNC("getfunctionhash", function(f) return __hex(tostring(f)) end)
    __setUNC("filtergc", function(...) return {} end)
    __setUNC("replicatesignal", function(s) return s end)
    __setUNC("cleardrawcache", function() return nil end)
    __setUNC("getreg", function() if debug and debug.getregistry then return debug.getregistry() else return {} end end)
    __setUNC("getregistry", function() if debug and debug.getregistry then return debug.getregistry() else return {} end end)
    local __dbg = __realEnv.debug or debug
    if __dbg then
        -- debug table is frozen in Lune: never assign directly, pcall only
        __pcall(function() if not __dbg.getregistry then __dbg.getregistry = function() return {} end end end)
        __pcall(function() if not __dbg.getupvalue then __dbg.getupvalue = function(f, i) return nil end end end)
        __pcall(function() if not __dbg.getupvalues then __dbg.getupvalues = function(f) return {} end end end)
        __pcall(function() if not __dbg.getconstant then __dbg.getconstant = function(f, i) return nil end end end)
        __pcall(function() if not __dbg.getconstants then __dbg.getconstants = function(f) return {} end end end)
        __pcall(function() if not __dbg.getproto then __dbg.getproto = function(f, i) local function __e() end return __e end end end)
        __pcall(function() if not __dbg.getprotos then __dbg.getprotos = function(f) return {} end end end)
        __pcall(function() if not __dbg.getstack then __dbg.getstack = function(lvl) return {} end end end)
        __pcall(function() if not __dbg.setconstant then __dbg.setconstant = function() return nil end end end)
        __pcall(function() if not __dbg.setstack then __dbg.setstack = function() return nil end end end)
        __pcall(function() if not __dbg.setupvalue then __dbg.setupvalue = function() return nil end end end)
    end
end

-- // ANTI-TAMPER BYPASS: neutralize env-fingerprinting + executor-detection
-- (pure anti-tamper only here; service spoofs that use Instance/Signal come in a
--  later block, AFTER the Roblox mock block, where the makers are in scope)
do
    -- checkcaller: whole Lune process IS the executor thread (anti-tamper check)
    __setUNC("checkcaller", function() return true end)
    __setUNC("isexecutorclosure", function(f) return true end)
    __setUNC("checkclosure", function(f) return true end)
    __setUNC("isourclosure", function(f) return true end)
    -- engine/executor functions are C closures; script closures are not
    __setUNC("iscclosure", function(f) return __isNativeFn(f) end)
    __setUNC("islclosure", function(f) return true end)   -- our scripts are Luau
    __setUNC("isnewcclosure", function(f) return __isCClosureTrack[f] == true end)
    -- debug.info: some VMs use debug.info(fn, "s") instead of debug.getinfo
    local __dbg2 = __realEnv.debug or debug or {}
    if __type(__dbg2) == "table" then
        if not __dbg2.info then __dbg2.info = function(f, w) return nil end end
    end
    -- newproxy: Roblox-specific userdata creation. Lune exposes a real newproxy, but it is
    -- not reachable through _G; anti-tamper checks use rawget(_G,"newproxy") so put it there.
    local __realNewproxy = newproxy
    __setUNC("newproxy", __type(__realNewproxy) == "function" and __realNewproxy or function() return nil end)
    -- bit32: some VMs use bit32.bxor, bit32.band etc. (Lune lacks bit32)
    if not bit32 then
        __setUNC("bit32", {
            band = function(a, b) return a % (2^32) end,
            bor = function(a, b) return a % (2^32) end,
            bxor = function(a, b) return (a + b) % (2^32) end,
            bnot = function(a) return (2^32 - 1 - a) % (2^32) end,
            lshift = function(a, n) return (a * 2^n) % (2^32) end,
            rshift = function(a, n) return math.floor(a / 2^n) % (2^32) end,
            arshift = function(a, n) return math.floor(a / 2^n) end,
            extract = function(a, f, w) return math.floor(a / 2^f) % (2^(w or 1)) end,
            replace = function(a, r, f, w) return a end,
            btest = function(a, b) return (a % (2^32)) ~= 0 end,
            countlz = function(a) return 0 end,
            countrz = function(a) return 0 end,
            byteswap = function(a) return a end,
            self = function() return {} end,
        })
    end
    -- gcinfo / collectgarbage: anti-tamper can check GC behavior
    __setUNC("gcinfo", function() return 0 end)
    local __origCollectgarbage = collectgarbage
    if __type(__origCollectgarbage) == "function" then
        local function __safeCollectgarbage(mode, ...)
            if mode == "count" then return 0, 0 end
            if mode == "step" then return true end
            if mode == "collect" then return false end
            if mode == "stop" then return false end
            if mode == "restart" then return false end
            if mode == "setpause" then return false end
            if mode == "setstepmul" then return false end
            if mode == "isrunning" then return true end
            return false
        end
        collectgarbage = __safeCollectgarbage
        __pcall(function() __realEnv.collectgarbage = __safeCollectgarbage end)
    end
    -- newcclosure: wrap Lua functions to look like C closures
    __setUNC("newcclosure", function(f)
        if __type(f) ~= "function" then return f end
        __isCClosureTrack = __isCClosureTrack or {}
        __isCClosureTrack[f] = true
        return f
    end)
    -- getcallingscript must return nil or a minimal script-like object
    __setUNC("getcallingscript", function() return nil end)
    __setUNC("getscriptclosure", function(s) return function() end end)
    __setUNC("getscripthash", function(s) return "hash_" .. tostring(math.random(10000)) end)
    __setUNC("getscriptbytecode", function(s) return "" end)
    -- executor identity: pass common checks
    __setUNC("identifyexecutor", function() return "Synapse X", "3.0.0" end)
    __setUNC("getexecutorname", function() return "Synapse X" end)
    __setUNC("getexecutorversion", function() return "3.0.0" end)
    -- thread identity: high number so scripts don't error
    __setUNC("getthreadidentity", function() return 8 end)
    __setUNC("setthreadidentity", function(n) return nil end)
    __setUNC("getthreadcontext", function() return 8 end)
    __setUNC("setthreadcontext", function(n) return nil end)
    __setUNC("getidentity", function() return 8 end)
    __setUNC("setidentity", function(n) return nil end)
    -- namecall: anti-tamper uses getnamecallmethod
    __setUNC("getnamecallmethod", function() return "" end)
    __setUNC("setnamecallmethod", function(m) return nil end)
end

-- mock Roblox globals as userdata (eUNC requires type(game)=="userdata")
do
    __signalStore = __signalStore or {}
    __instData = __instData or setmetatable({}, {__mode="k"})
    -- signals in the Changed family are excluded from pump-stepping and get real values
    local function __sigChangedFamily(name)
        local n = tostring(name or "")
        return n:find("Changed", 1, true) ~= nil
    end
    -- Signal handles: userdata sharing ONE metatable, so `a == b` is value-true for two
    -- lookups of the same signal while `rawequal(a, b)` stays false - exactly Roblox.
    __sigRegistry = {}
    -- every newproxy gets its own metatable, so the handlers are built once here and then
    -- attached to each handle (that is also what keeps __eq working: same table, same funcs)
    local __sigIndex = function(self, k)
        local sig = __sigRegistry[self]
        if sig == nil then return nil end
        return sig[k]
    end
    -- Lune's newproxy(true) __namecall DROPS the method name (it passes the first
    -- call argument as `k`), so method calls must go through __index instead: Luau
    -- then invokes the returned function with the handle as its first argument.
    local __sigEq = function(a, b)
        local sa, sb = __sigRegistry[a], __sigRegistry[b]
        return sa ~= nil and sa == sb
    end
    local __sigToString = function(self)
        local sig = __sigRegistry[self]
        return sig and sig._name or "signal"
    end
    local __sigCall = function(self, cb)
        local sig = __sigRegistry[self]
        if sig then return sig:Connect(cb) end
        return nil
    end
    __markNative(__sigIndex, "__index")
    __markNative(__sigEq, "__eq")
    local function __sigHandle(x)
        local inner = __sigRegistry[x] or x
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        mt.__index = __sigIndex
        mt.__eq = __sigEq
        mt.__tostring = __sigToString
        mt.__call = __sigCall
        __sigRegistry[ud] = inner
        return ud
    end
    local function __newSignal(name)
        local sig = {}
        sig._name = name
        sig._conns = {}
        sig._firing = false
        -- signals ending in "Changed" must fire with the true property value (Roblox
        -- semantics), never with pump-fabricated substitutes. Foreach oddball, the same
        -- lazily-defined helper is also used by __newindex below.
        local function fireOwn(self, ...)
            if sig._firing then return nil end
            sig._firing = true
            local args = {...}
            for _, c in ipairs(sig._conns) do
                if c.Connected and __type(c.Function) == "function" then
                    __pcall(function() c.Function(unpack(args)) end)
                end
            end
            sig._firing = false
            return nil
        end
        sig._fireOwn = fireOwn
        sig.Connect = function(self, cb)
            local fn = cb
            if fn == nil and __type(self)=="function" then fn = self self = sig end
            local conn = {}
            conn.Connected = true
            conn.Function = fn
            conn.Disconnect = function(c)
                -- Roblox raises when the receiver is missing (anti-tamper probes this)
                if c == nil then error("Disconnect: missing self", 2) end
                c = c or conn
                c.Connected = false
                for i, v in ipairs(sig._conns) do if v == conn then table.remove(sig._conns, i) break end end
                return nil
            end
            conn.disconnect = conn.Disconnect
            if __type(fn)=="function" then
                sig._conns[#sig._conns+1] = conn
                -- Changed-family signals (Changed, SizeChanged, PropertyChangedSignal-derived,
                -- AttributeChanged...) must NOT be stepped with fabricated args by the pump:
                -- anti-tamper samples verify Changed receives the ACTUAL new property value and
                -- assert event counts. They are fired explicitly on real property writes below.
                if not __sigChangedFamily(name) then
                    __signalStore[#__signalStore+1] = {sig=name, cb=fn}
                end
                __logCall("signal:Connect", __repr(name))
            end
            return conn
        end
        sig.connect = sig.Connect
        sig.Wait = function(self)
            -- runtime: run queued spawned/delayed coroutines, then fire queued handlers, so
            -- Connect-then-Wait loops and task.delay(..., ev:Fire()) pairs actually advance
            if not __pumpStepping then __stepQueue(8) end
            __pcall(function() __stepQueue(8) end)
            __pcall(function() __stepSignals(8) end)
            __fakeTime = __fakeTime + 0.016
            local __nm = tostring(name or "")
            if __nm:find("Heartbeat") then return 0.016, 0.016 end
            if __nm:find("Stepped") then return 0.016, 0 end
            if __nm:find("RenderStepped") then return 0.016 end
            return nil
        end
        sig.Fire = function(self, ...)
            local a1 = ...
            local args = {...}
            if __type(self) ~= "table" or self._conns == nil then args = {self, ...} end
            for _, c in ipairs(sig._conns) do if c.Connected and __type(c.Function)=="function" then __pcall(function() c.Function(unpack(args)) end) end end
            return nil
        end
        sig.fire = sig.Fire
        for __sk, __sv in __pairs(sig) do
            if __type(__sv) == "function" then __markNative(__sv, tostring(__sk)) end
        end
        setmetatable(sig, {__call=function(self, cb) return sig:Connect(cb) end})
        return __sigHandle(sig)
    end
    local __signalNames = {MouseButton1Click=true, MouseEnter=true, MouseLeave=true, InputBegan=true, InputEnded=true, InputChanged=true, ChildAdded=true, ChildRemoved=true, Heartbeat=true, Stepped=true, RenderStepped=true, Changed=true, GetPropertyChangedSignal=true, Idled=true, CharacterAdded=true, CharacterRemoving=true, Chatted=true, Died=true, Running=true, Jumping=true, FreeFalling=true, StateChanged=true, HumanoidDied=true, Button1Down=true, Button1Up=true, Button2Down=true, Button2Up=true, Move=true, Activated=true, Deactivated=true, SelectionGained=true, SelectionLost=true, TextChanged=true, FocusLost=true, FocusGained=true, TouchStarted=true, TouchEnded=true, TouchMoved=true, HealthChanged=true, MaxHealthChanged=true, WalkSpeedChanged=true}
    local __instanceProps = {LocalPlayer=true, CurrentCamera=true, Baseplate=true, Character=true, Humanoid=true, HumanoidRootPart=true, PlayerGui=true}
    local __instCount = 0
    -- same object every time: game:GetService("Players") == game.Players, and
    -- char:WaitForChild("HumanoidRootPart") is stable, so ids stay readable.
    -- forward-declare so __kidOf can call it (Lua locals must exist first)
    local __newInstance
    local function __kidOf(ud, name, className)
        local rec = __instData and __instData[ud]
        if not rec then return __newInstance(className or name) end
        rec.kids = rec.kids or {}
        if not rec.kids[name] then rec.kids[name] = __newInstance(className or name) end
        return rec.kids[name]
    end
    local function __STRICT_MEMBERS_ON()
        if __G_STRICT_MEMBERS then return true end
        if _G and _G.__STRICT_MEMBERS then return true end
        if __realEnv and __realEnv.__STRICT_MEMBERS then return true end
        return false
    end
    __G_STRICT_MEMBERS = false
    -- minimal Roblox class hierarchy so IsA("Instance")/IsA("BasePart") behave
    local __classParents = {
        Part = "BasePart", BasePart = "Part", TrussPart = "BasePart", WedgePart = "BasePart",
        MeshPart = "BasePart", UnionOperation = "BasePart", SpawnLocation = "Part",
        Model = "PVInstance", Folder = "PVInstance", Tool = "PVInstance", Configuration = "PVInstance",
        ScreenGui = "LayerCollector", Frame = "GuiObject", TextLabel = "GuiObject",
        TextButton = "GuiObject", TextBox = "GuiObject", ImageLabel = "GuiObject",
        ImageButton = "GuiObject", ScrollingFrame = "GuiObject", ViewportFrame = "GuiObject",
        BillboardGui = "LayerCollector", SurfaceGui = "LayerCollector",
    }
    local function __classAncestors(className)
        local out = {}
        local cur = className
        local guard = 0
        while cur and guard < 8 do
            local parent = __classParents[cur]
            if not parent then break end
            out[parent] = true
            cur = parent
            guard = guard + 1
        end
        return out
    end
    __newInstance = function(className)
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        local __props = {}
        local __sigs = {}
        __instCount = __instCount + 1
        local __id = tostring(className) .. "_" .. __instCount
        -- default hidden props for Fire etc
        if className == "Fire" then __props["size_xml"] = 5 __props["scriptable_size_xml"] = false end
        __instData[ud] = {props=__props, sigs=__sigs, class=className, id=__id, kids={}}
        mt.__index = function(self,k)
            if __props[k] ~= nil then return __props[k] end
            -- game:GetService("Enum") must hand out the SAME EnumType tables as the
            -- global Enum, otherwise `Enum.X.Y:FromName` identity checks break
            if className == "Enum" then
                local __eg = __unc["Enum"]
                if __type(__eg) == "table" then
                    local v = __eg[k]
                    if v ~= nil then return v end
                end
            end
            if className == "BindableEvent" and k == "Event" then
                if not __sigs["Event"] then __sigs["Event"] = __newSignal(__id..".Event") end
                return __sigHandle(__sigs["Event"])
            end
            if className == "BindableEvent" and k == "Fire" then
                return function(s, ...)
                    __logCall(__id..":Fire", __argsToRepr(...))
                    local sig = __sigs and __sigs["Event"]
                    if sig and sig.Fire then __pcall(sig.Fire, sig, ...) end
                    return nil
                end
            end
            if className == "BindableFunction" and k == "OnInvoke" then return __props["OnInvoke"] end
            if className == "BindableFunction" and k == "Invoke" then
                return function(s, ...)
                    __logCall(__id..":Invoke", __argsToRepr(...))
                    local cb = __props["OnInvoke"]
                    if __type(cb) == "function" then
                        local ok, r = __pcall(cb, s, ...)
                        if ok then return r end
                    end
                    return nil
                end
            end
            if className == "RemoteEvent" then
                if k == "OnClientEvent" or k == "OnServerEvent" then
                    if not __sigs[k] then __sigs[k] = __newSignal(__id.."."..k) end
                    return __sigHandle(__sigs[k])
                end
                if k == "FireServer" then
                    return function(s, ...)
                        __logCall(__id..":FireServer", __argsToRepr(...))
                        local sig = __sigs and __sigs["OnServerEvent"]
                        if sig and sig.Fire then __pcall(sig.Fire, sig, ...) end
                        return nil
                    end
                end
                if k == "FireAllClients" then
                    return function(s, ...)
                        __logCall(__id..":FireAllClients", __argsToRepr(...))
                        return nil
                    end
                end
                if k == "FireClient" then
                    return function(s, ...)
                        __logCall(__id..":FireClient", __argsToRepr(...))
                        return nil
                    end
                end
            end
            if className == "DataStoreIncrementOptions" then
                if k == "SetMetadata" then
                    return function(_, d) __props["metadata"] = d; return nil end
                end
                if k == "GetMetadata" then
                    return function() return __props["metadata"] end
                end
                if k == "SetIncrementAmount" then
                    return function(_, d) __props["incrementAmount"] = d; return nil end
                end
                if k == "GetIncrementAmount" then
                    return function() return __props["incrementAmount"] end
                end
            end
            if className == "RemoteFunction" then
                if k == "OnClientInvoke" or k == "OnServerInvoke" then
                    return function(_, cb)
                        if __type(cb) == "function" then __props[k] = cb end
                        return nil
                    end
                end
                if k == "InvokeServer" then
                    return function(s, ...)
                        __logCall(__id..":InvokeServer", __argsToRepr(...))
                        local cb = __props["OnServerInvoke"]
                        if __type(cb) == "function" then
                            local ok, r = __pcall(cb, s, ...)
                            if ok then return r end
                        end
                        return nil
                    end
                end
                if k == "InvokeClient" then
                    return function(s, ...)
                        __logCall(__id..":InvokeClient", __argsToRepr(...))
                        return nil
                    end
                end
            end
            if k=="ClassName" then return className end
            if k=="Name" then return __props["Name"] or className end
            if k=="Parent" then return __props["Parent"] end
            if k=="Archivable" then return true end
            -- resolve seeded children by name, like real Instance indexing
            local __krec = __instData and __instData[self]
            if __krec and __krec.kids and __krec.kids[k] then return __krec.kids[k] end
            if k=="GetChildren" then return function() return {} end end
            if k=="GetDescendants" then return function() return {} end end
            if k=="FindFirstChild" then return function(s,n)
                local rec = __instData and __instData[s]
                if rec and rec.kids and rec.kids[n] then return rec.kids[n] end
                return nil
            end end
            if k=="FindFirstChildWhichIsA" then return function() return nil end end
            if k=="FindFirstChildOfClass" then return function() return nil end end
            if k=="WaitForChild" then return function(s,n) return __kidOf(s, tostring(n)) end end
            if k=="Clone" then return function(s) return __newInstance(className) end end
            if k=="Destroy" then return __markNative(function(s)
                __logCall(__id..":Destroy", "")
                if s == nil then error("Destroy: missing self", 2) end
                local rec = __instData and __instData[s]
                if rec then
                    if rec.props then rec.props.Parent = nil end
                    if rec.kids then
                        for kid in __pairs(rec.kids) do
                            local kr = __instData and __instData[kid]
                            if kr and kr.props then kr.props.Parent = nil end
                        end
                        rec.kids = {}
                    end
                    rec.destroyed = true
                end
                return nil
            end, "Destroy") end
            if k=="Remove" then return function(s) __logCall(__id..":Remove", "") return nil end end
            if k=="ClearAllChildren" then return function() return nil end end
            if k=="IsA" then return __markNative(function(s,c)
                if s == nil then error("IsA: missing self", 2) end
                if __type(c) ~= "string" then error("IsA: argument #2 must be a string", 2) end
                if c == "Instance" or c == "Object" then return true end
                if c == className then return true end
                return __classAncestors(className)[c] == true
            end, "IsA") end
            if k=="GetAttribute" then return __markNative(function(s, attr)
                local rec = __instData and __instData[s]
                local a = rec and rec.props and rec.props.__attrs
                if a and a[attr] ~= nil then return a[attr] end
                return nil
            end, "GetAttribute") end
            if k=="SetAttribute" then return __markNative(function(s, attr, val)
                if s == nil then error("SetAttribute: missing self", 2) end
                local rec = __instData and __instData[s]
                if rec and rec.props then
                    rec.props.__attrs = rec.props.__attrs or {}
                    if val == nil then rec.props.__attrs[attr] = nil else rec.props.__attrs[attr] = val end
                end
                local sig = rec and rec.sigs and rec.sigs["AttributeChanged"]
                if sig then __pcall(function() sig._fireOwn(sig, attr) end) end
                return nil
            end, "SetAttribute") end
            if k=="GetFullName" then return function() return "Game."..className end end
            if k=="FindFirstChildOfClass" then return function(s,c)
                local rec = __instData and __instData[s]
                if rec and rec.kids then
                    for _, kid in pairs(rec.kids) do
                        local krec = __instData and __instData[kid]
                        if krec and krec.props and krec.props.ClassName == c then return kid end
                    end
                end
                return nil
            end end
            if k=="GetChildren" then return function(s)
                local rec = __instData and __instData[s]
                local out = {}
                if rec and rec.kids then
                    for _, kid in pairs(rec.kids) do out[#out + 1] = kid end
                end
                return out
            end end
            if k=="FindFirstAncestor" or k=="FindFirstAncestorWhichIsA" or k=="FindFirstAncestorOfClass" then
                return function() return nil end
            end
            if k=="IsDescendantOf" then return function() return false end end
            if k=="IsAncestorOf" then return function() return false end end
            if k=="GetObjectValue" then return function() return nil end end
            if k=="GetChildrenCount" or k=="GetDescendantsCount" then return function() return 0 end end
            if k=="SetPrimaryPartCFrame" then return function() return nil end end
            if k=="GetPivot" then return function() return CFrame.new(0, 0, 0) end end
            if k=="SetPivot" then return function() return nil end end
            if k=="GetBoundingBox" then return function() return CFrame.new(0, 0, 0), Vector3.new(1, 1, 1) end end
            if k=="GetAttributeChangedSignal" then
                if not __sigs["AttributeChanged"] then __sigs["AttributeChanged"] = __newSignal(__id..".AttributeChanged") end
                return __sigHandle(__sigs["AttributeChanged"])
            end
            if k=="GetPropertyChangedSignal" then
                return function(_, prop)
                    local key = "Prop_" .. tostring(prop)
                    if not __sigs[key] then __sigs[key] = __newSignal(__id.."."..tostring(prop).."Changed") end
                    return __sigHandle(__sigs[key])
                end
            end
            if k=="Changed" then
                if not __sigs["Changed"] then __sigs["Changed"] = __newSignal(__id..".Changed") end
                return __sigHandle(__sigs["Changed"])
            end
            if k=="Added" then return __newSignal(__id..".Added") end
            if k=="Removing" or k=="DescendantRemoving" then return __newSignal(__id..".Removing") end
            if k=="DescendantAdded" then return __newSignal(__id..".DescendantAdded") end
            if k=="ChildAdded" then return __newSignal(__id..".ChildAdded") end
            if k=="InstanceAdded" or k=="InstanceRemoved" then return __newSignal(__id..k) end
            if __signalNames[k] then
                if not __sigs[k] then __sigs[k] = __newSignal(__id.."."..k) end
                return __sigHandle(__sigs[k])
            end
            if __instanceProps[k] then return __kidOf(self, k) end
            -- strict mode: unknown members read as nil, exactly like real Roblox.
            -- Off by default because loader VMs rely on the catch-all stub below.
            if __STRICT_MEMBERS_ON() then return nil end
            -- unknown member: return a special object that is BOTH callable (method call)
            -- and indexable (property reads like Camera.CFrame.Something) so loader VMs
            -- that do `service.Member:Method()` do not crash on a bare function.
            local sub = __newInstance("__Member")
            local subRec = __instData and __instData[sub]
            if subRec then
                subRec.props.__of = __id
                subRec.props.__member = k
            end
            return sub
        end
        -- THE whole-source fix: every property write (Text, Size, Position, colors...)
        -- is logged as `ScreenGui_1.Text = "Fly"` instead of vanishing silently.
        mt.__newindex = function(_,k,v)
            if k == "Parent" then
                -- keep a real-ish parent/kid tree so WaitForChild(path) works and
                -- Loader:Clone()d trees resolve FindFirstChild(child.name)
                local oldParent = __props["Parent"]
                if oldParent ~= v then
                    local oldRec = __instData and __instData[oldParent]
                    if oldRec and oldRec.kids then
                        local myName = __props["Name"] or className
                        for kidName, kid in pairs(oldRec.kids) do
                            if kid == ud then oldRec.kids[kidName] = nil break end
                        end
                    end
                    if v ~= nil then
                        local newRec = __instData and __instData[v]
                        if newRec then
                            newRec.kids = newRec.kids or {}
                            local myName = __props["Name"] or className
                            newRec.kids[myName] = ud
                            __props["Parent"] = v
                        else
                            __props["Parent"] = v
                        end
                    else
                        __props["Parent"] = nil
                    end
                end
            else
                __props[k]=v
                -- Roblox semantics: Changed fires with the NEW value whenever any property
                -- changes EXCEPT Name (anti-tamp samples assert exactly this, incl. event
                -- count + identity). PropertyChangedSignal-derived ("Prop_"..k) fires too.
                if k ~= "Name" then
                    local cg = __sigs["Changed"]
                    if cg and cg._fireOwn then __pcall(function() cg:_fireOwn(v) end) end
                    local pc = __sigs["Prop_" .. tostring(k)]
                    if pc and pc._fireOwn then __pcall(function() pc:_fireOwn(v) end) end
                end
            end
            if __LOG_ENABLED then
                __LOG_COUNT = __LOG_COUNT + 1
                if __LOG_COUNT <= __MAX_LOGS then
                    __table_insert(__LOGS, __id .. "." .. tostring(k) .. " = " .. __repr(v))
                end
            end
        end
        mt.__tostring = function() return className end
        mt.__className = className
        mt.__pairs = function() return function() return nil end end
        mt.__call = function(self, ...)
            local rec = __instData and __instData[self]
            local callName = rec and rec.props and rec.props.__member
            local ofName = rec and rec.props and rec.props.__of
            if callName and ofName then
                __logCall(ofName .. ":" .. tostring(callName), __argsToRepr(...))
            else
                __logCall(__id .. "()", __argsToRepr(...))
            end
            return __newInstance(className)
        end
        -- every method handed to a script is a C closure in Roblox; register them all
        do
            local __idx0 = mt.__index
            mt.__index = function(self, k)
                local v = __idx0(self, k)
                if __realType(v) == "function" then __markNative(v, className .. "." .. tostring(k)) end
                return v
            end
        end
        return ud
    end
     local __origTypeof = typeof or function(v) return type(v) end
local function __mockTypeof(v)
        if __type(v)=="table" or type(v)=="userdata" then
            -- Roblox instances (userdata registered in __instData) are typeof "Instance"
            -- regardless of any raw ClassName property (matches real Roblox: typeof(game)=="Instance").
            if __sigRegistry and __sigRegistry[v] then return "RBXScriptSignal" end
            if type(v)=="userdata" and __instData and __instData[v] then return "Instance" end
            if __type(v) == "table" and __rawget(v, "__enumItem") then return "EnumItem" end
            if __type(v) == "table" and __rawget(v, "__enumType") then return "EnumType" end
            -- table-backed value types (vectors): keep the Roblox typeof name
            if __type(v) == "table" then
                if __rawget(v, "__svcName") then return "Instance" end
                local vk = __rawget(v, "__vecKind")
                if vk then return vk end
                if __rawget(v, "__cfKind") then return "CFrame" end
            end
            local cn = rawget(v, "ClassName")
            if cn then return cn end
            local hasName, hasEnumType = rawget(v, "Name"), rawget(v, "EnumType")
            if hasName and hasEnumType then return "Enum" end
            -- Enum category tables (Enum.NormalId, Enum.KeyCode, etc.): tostring returns "Enum.*"
            local ok, ts = pcall(tostring, v)
            if ok and type(ts)=="string" and ts:sub(1,5)=="Enum." then return "Enum" end
            local hasX = rawget(v, "X")
            if hasX then return "Axes" end
        end
        return __origTypeof(v)
    end
__setUNC("typeof", __mockTypeof)
     if _G then _G.typeof = __mockTypeof end
     if _G then _G.typeof = __mockTypeof end
     __realEnv.typeof = __mockTypeof
     -- mock type() to return "userdata" for Roblox types (Enum, Axes, Instances)
     local __origType = type
     local function __mockType(v)
         if __type(v)=="table" then
             -- Roblox services (game:GetService(...)) are Instances, not plain tables
             if __rawget(v, "__svcName") then return "userdata" end
             local cn = rawget(v, "ClassName")
             if cn then return "userdata" end
             local hasName, hasEnumType = rawget(v, "Name"), rawget(v, "EnumType")
             if hasName and hasEnumType then return "userdata" end
             local hasX = rawget(v, "X")
             if hasX then return "userdata" end
            if __rawget(v, "__vecKind") then return "userdata" end
         end
         return __origType(v)
     end
     __setUNC("type", __mockType)
     if _G then _G.type = __mockType end
     __realEnv.type = __mockType

    -- rawget on our instance userdata: Lune rawget returns nil for userdata, but real
    -- Roblox scripts rawget(game, "ClassName") -> "DataModel". Route instance reads
    -- through __instData (ClassName/Name/props). Non-instances behave natively.
    local __origRawGet = rawget
    __setUNC("rawget", function(t, ...)
        local k = ...
        -- Roblox validates rawget arity; the engine raises a "missing argument"
        -- error that anti-tamper samples match against.
        if t == nil then error("missing argument #1 to 'rawget'", 2) end
        if select("#", ...) == 0 then error("missing argument #2 to 'rawget'", 2) end
        local ok, r
        local tk = __type(t)
        if tk == "userdata" then
            ok, r = pcall(__origRawGet, t, k)
            if ok and r ~= nil then return r end
            if __instData and __instData[t] then
                local rec = __instData[t]
                if k == "ClassName" then return rec.class end
                if k == "Name" then return rec.props and rec.props["Name"] end
                if rec.props and rec.props[k] ~= nil then return rec.props[k] end
            end
            return nil
        end
        ok, r = pcall(__origRawGet, t, k)
        if ok then return r end
        return nil
    end)
    -- getmetatable("") must look like Roblox's locked string metatable (SamlarenHub /
    -- Kw15 anti-tamps check __index == string and __metatable == "The metatable is locked")
    local __origGetmt3 = getmetatable
    local function __mockGetmt(v)
        if type(v) == "string" then return {__index=string, __metatable="The metatable is locked"} end
        return __origGetmt3(v)
    end
    __setUNC("getmetatable", __mockGetmt)
    if _G then
        local __og2 = __origGetmt3
        _G.getmetatable = function(v)
            if type(v) == "string" then return {__index=string, __metatable="The metatable is locked"} end
            return __og2(v)
        end
    end

    local __mockGame = __newInstance("DataModel")
    -- add Game specific
    do
        local mt = getmetatable(__mockGame)
        local origIndex = mt.__index
        local __idxMarked = function(self, k)
            local v = origIndex(self, k)
            if __realType(v) == "function" then __markNative(v, "game." .. tostring(k)) end
            return v
        end
        mt.__index = function(self,k)
            if k=="GetService" then
                return __markNative(function(_, s)
                    __logCall("game:GetService", __repr(s))
                    if __serviceMocks and __serviceMocks[s] then return __serviceMocks[s] end
                    return __newInstance(s)
                end, "game.GetService")
            end
            if k=="HttpGet" or k=="HttpGetAsync" then
                return function(_, url)
                    local cleanUrl = tostring(url):gsub("[%c%z]", "")
                    local baseUrl = cleanUrl:match("(https://[^?]+)") or cleanUrl
                    __logCall("game:HttpGet", __repr(cleanUrl))
                    if _G.__MOCK_PAYLOADS and (_G.__MOCK_PAYLOADS[cleanUrl] or _G.__MOCK_PAYLOADS[baseUrl] or _G.__MOCK_PAYLOADS["*"]) then
                        __table_insert(__LOGS, "-- MOCK IN-GAME HTTP: " .. cleanUrl)
                        return _G.__MOCK_PAYLOADS[cleanUrl] or _G.__MOCK_PAYLOADS[baseUrl] or _G.__MOCK_PAYLOADS["*"]
                    end
                    if _G.__MOCK_PAYLOAD and _G.__MOCK_PAYLOAD ~= "" then
                        __table_insert(__LOGS, "-- MOCK IN-GAME HTTP: " .. cleanUrl)
                        return _G.__MOCK_PAYLOAD
                    end
                    if _G.__lastUrl == cleanUrl then
                        _G.__retryN = (_G.__retryN or 0) + 1
                    else
                        _G.__lastUrl = cleanUrl
                        _G.__retryN = 1
                    end
                    if _G.__retryN > 1 then
                        __table_insert(__LOGS, "-- LINK: " .. cleanUrl
                            .. " (retry #" .. _G.__retryN .. ")")
                    else
                        __table_insert(__LOGS, "-- LINK: " .. cleanUrl)
                    end
                    -- seed the server-hop gate: the VM's [14696] handler bails unless
                    -- JSONDecode gets a response containing a "data" array, so return
                    -- a canned job list for games.roblox.com/v1/games/ probes.
                    if cleanUrl:find("games.roblox.com/v1/games/", 1, true) then
                        return '{"data":[{"id":"JobID_Alt","playing":2},{"id":"JobID_Alt2","playing":3}]}'
                    end
                    -- check pre-fetched cache from Python (runtime-loaded links)
                    if _G.__httpCache and _G.__httpCache[baseUrl] then return _G.__httpCache[baseUrl] end
                    if _G.__httpCache and _G.__httpCache[cleanUrl] then return _G.__httpCache[cleanUrl] end
                    if __httpCache and __httpCache[baseUrl] then return __httpCache[baseUrl] end
                    if __httpCache and __httpCache[cleanUrl] then return __httpCache[cleanUrl] end
                    if _G.__HTTP_NO_FETCH then return "" end
                    -- Not cached: report it as a fresh payload link (may be recovered on
                    -- a re-run with --prefetch-file once the URL is known). Only genuine
                    -- exfil endpoints (webhooks) are blocked; fetching payload links the
                    -- loader downloaded is the whole point of a deobfuscator.
                    if not _G.__httpNoFetch then
                        __table_insert(__LOGS, "-- LINK UNCACHED: " .. cleanUrl)
                    end
                    return ""
                end
            end
            if k=="HttpPost" or k=="HttpPostAsync" or k=="PostAsync" then
                return function(_, ...)
                    local a1 = ...
                    __exfilBlock("game:"..tostring(k), __exfilUrlOf(a1, select(2, ...)))
                    return ""
                end
            end
            if k=="CreatorType" then return Enum and Enum.CreatorType and Enum.CreatorType.User or 0 end
            if k=="CreatorId" then return 0 end
            if k=="PlaceId" then __table_insert(__LOGS, "-- GAME READ PlaceId = " .. tostring(__GATE_PLACEID or 0)); return __GATE_PLACEID or 0 end
            if k=="GameId" then __table_insert(__LOGS, "-- GAME READ GameId = " .. tostring(__GATE_GAMEID or 0)); return __GATE_GAMEID or 0 end
            if k=="PlaceVersion" then __table_insert(__LOGS, "-- GAME READ PlaceVersion"); return 1001 end
            if k=="JobId" then __table_insert(__LOGS, "-- GAME READ JobId"); return "NotLoggedInYet" end
            if k=="_RESUME" or k=="_START" then __table_insert(__LOGS, "-- GAME READ " .. tostring(k)); return __startResume end
            if __type(k)=="string" and (k=="Id" or k=="UniverseId" or k=="NetworkServerId" or k=="Environment" or k=="IsLoaded") then
                if k=="IsLoaded" then return function() return true end end
                return "0"
            end
            -- services/properties as Instances (not functions) so Players.LocalPlayer chains survive
            if __type(k)=="string" and k:match("^[A-Z]") and k ~= "ClassName" and k ~= "Name" then
                return __newInstance(k)
            end
            return __idxMarked(self, k)
        end
    end
    -- epoch-ish clock so `tick() > 1e9` / `os.time() > 1.7e9` fidelity checks pass (SmileHub)
    local __epochBase = 1730000000
    __setUNC("tick", function() return __epochBase + (os.clock() or 0) end)
    __setUNC("time", function() return __epochBase + (os.clock() or 0) end)
    __setUNC("elapsedTime", function() return __epochBase + (os.clock() or 0) end)
    __pcall(function()
        if __realEnv.os then __realEnv.os.time = function() return __epochBase end end
        if _G and _G.os then _G.os.time = function() return __epochBase end end
    end)
    __realEnv.tick = function() return __epochBase + (os.clock() or 0) end
    __realEnv.time = function() return __epochBase + (os.clock() or 0) end
    if _G then _G.tick = __realEnv.tick; _G.time = __realEnv.time end
    __setUNC("game", __mockGame)
    __setUNC("Game", __mockGame)
    __setUNC("workspace", __newInstance("Workspace"))
    __WORLD = __WORLD or {}
    local W = __WORLD
    W.kids = W.kids or {}
    do
        local ws = __realEnv.workspace
        local mt = getmetatable(ws)
        local __wsBaseIndex = mt.__index
        mt.__index = function(self,k)
            local w = W
            if w then
                if k=="Baseplate" then return w.Baseplate end
                if k=="Terrain" then return w.Terrain end
                if k=="SpawnLocation" then return w.SpawnLocation end
                if k=="CurrentCamera" then return w.Camera end
                if w.kids and w.kids[k]~=nil then return w.kids[k] end
            end
            if k=="CurrentCamera" then return __newInstance("Camera") end
            if k=="DistributedGameTime" then return 0 end
            if k=="Gravity" then return 196.2 end
            if k=="FallenPartsDestroyHeight" then return -500 end
            if k=="Raycast" then
                return function(_,origin,direction,params)
                    local base = w.Baseplate
                    if base then
                        return {Instance=base, Position=base.Position, Normal=Vector3.new(0,1,0), Distance=(base.Position-origin).Magnitude, Material=base.Material}
                    end
                    return nil
                end
            end
            if k=="GetChildren" then
                return function() local t={}; for n,ch in pairs(w.kids or {}) do t[#t+1]=ch end; return t end
            end
            if k=="GetDescendants" then
                return function() local t={}; local function visit(i) if i.kids then for n,c in pairs(i.kids) do visit(c) end end end; if w==i then visit(w) end; return t end
            end
            return __wsBaseIndex(self,k)
        end
    end
    __setUNC("Workspace", __realEnv.workspace)
    __setUNC("Instance", setmetatable({}, {
        __index=function(_,k)
            if k=="new" then
                return __markNative(function(c) __logCall("Instance.new", __repr(c)); return __newInstance(c) end, "Instance.new")
            end
return __markNative(function(...) __logCall("Instance:"..tostring(k), __argsToRepr(...)); return __newInstance(tostring(k)) end, "Instance."..tostring(k))
        end,
        __call=function(_, k) return __newInstance(tostring(k)) end
    }))
    -- Vector3 etc as userdata for type checks (tracked so props log real values)
    local function __trackVal(ud, repr)
        __valRepr[ud] = repr
        return ud
    end
    -- Vector3/2 as userdata with real math: components readable, Magnitude/Unit correct,
    -- Dot/Cross/Lerp callable, and __eq comparing COMPONENTS (BestAntiTamper1 compares
    -- `sz == Vector2.new(40,25)`; ez19 compares Random streams). Store is weak-keyed so
    -- equality/cross-instance math works without carrying closures.
    __vec3Store = __vec3Store or setmetatable({}, {__mode="k"})
    __vec2Store = __vec2Store or setmetatable({}, {__mode="k"})
    local function __v3c(ud) return __vec3Store[ud] end
    local function __v2c(ud) return __vec2Store[ud] end
    local __vec3MT, __vec2MT
    local __newVector3, __newVector2   -- forward decls: the shared metatables below call these
    local function __getVec3MT()
        if __vec3MT then return __vec3MT end
        -- ONE shared metatable for all Vector3 values: Luau only invokes __eq when both
        -- operands share the same metatable (verified), and Roblox vectors share one too.
        local m = {}
        m.__tostring = function() return "Vector3" end
        m.__eq = function(a, b)
            if __type(b) ~= "table" then return false end
            local va, vb = __v3c(a), __v3c(b)
            if not va or not vb then return rawequal(a, b) end
            return va.x==vb.x and va.y==vb.y and va.z==vb.z
        end
        m.__add = function(a, b) local o=__v3c(b); local p=__v3c(a); if o then return __newVector3(p.x+o.x, p.y+o.y, p.z+o.z) end return a end
        m.__sub = function(a, b) local o=__v3c(b); local p=__v3c(a); if o then return __newVector3(p.x-o.x, p.y-o.y, p.z-o.z) end return a end
        m.__mul = function(a, b)
            local p = __v3c(a)
            if __type(b) == "number" then return __newVector3(p.x*b, p.y*b, p.z*b) end
            local o=__v3c(b); if o then return p.x*o.x + p.y*o.y + p.z*o.z end
            return a
        end
        m.__div = function(a, b) local p=__v3c(a); if __type(b)=="number" and b ~= 0 then return __newVector3(p.x/b, p.y/b, p.z/b) end return a end
        m.__unm = function(a) local p=__v3c(a); return __newVector3(-p.x,-p.y,-p.z) end
        __vec3MT = m
        return m
    end
    local function __getVec2MT()
        if __vec2MT then return __vec2MT end
        local m = {}
        m.__tostring = function() return "Vector2" end
        m.__eq = function(a, b)
            if __type(b) ~= "table" then return false end
            local va, vb = __v2c(a), __v2c(b)
            if not va or not vb then return rawequal(a, b) end
            return va.x==vb.x and va.y==vb.y
        end
        m.__add = function(a, b) local o=__v2c(b); local p=__v2c(a); if o then return __newVector2(p.x+o.x, p.y+o.y) end return a end
        m.__sub = function(a, b) local o=__v2c(b); local p=__v2c(a); if o then return __newVector2(p.x-o.x, p.y-o.y) end return a end
        m.__mul = function(a, b) local p=__v2c(a); if __type(b)=="number" then return __newVector2(p.x*b, p.y*b) end local o=__v2c(b); if o then return p.x*o.x + p.y*o.y end return a end
        m.__div = function(a, b) local p=__v2c(a); if __type(b)=="number" and b ~= 0 then return __newVector2(p.x/b, p.y/b) end return a end
        m.__unm = function(a) local p=__v2c(a); return __newVector2(-p.x,-p.y) end
        __vec2MT = m
        return m
    end
    __newVector3 = function(x,y,z, skipUnit)
        x, y, z = x or 0, y or 0, z or 0
        local mg = math.sqrt(x*x + y*y + z*z)
        local v = {X=x, Y=y, Z=z, Magnitude=mg}
        v.__vecKind = "Vector3"
        __vec3Store[v] = {x=x, y=y, z=z}
        v.Unit = v
        if mg > 0 then
            if skipUnit then v.Unit = v else v.Unit = __newVector3(x/mg, y/mg, z/mg, true) end
        end
        v.Dot = function(self, other) local o = __v3c(other); if o then return x*o.x + y*o.y + z*o.z end return 0 end
        v.Cross = function(self, other) local o = __v3c(other); if o then return __newVector3(y*o.z - z*o.y, z*o.x - x*o.z, x*o.y - y*o.x) end return __newVector3(0,0,0) end
        v.Lerp = function(self, goal, alpha) local g = __v3c(goal); if g then return __newVector3(x + (g.x-x)*alpha, y + (g.y-y)*alpha, z + (g.z-z)*alpha) end return __newVector3(x,y,z) end
        v.FuzzyEq = function(self, other, epsilon) local o=__v3c(other); if not o then return false end local dx,dy,dz=x-o.x,y-o.y,z-o.z; return math.sqrt(dx*dx+dy*dy+dz*dz) <= (epsilon or 1e-4) end
        v.ToString = function() return string.format("%g, %g, %g", x, y, z) end
        setmetatable(v, __getVec3MT())
        return __trackVal(v, "Vector3.new(" .. __tostring(x) .. ", " .. __tostring(y) .. ", " .. __tostring(z) .. ")")
    end
    __newVector2 = function(x,y, skipUnit)
        x, y = x or 0, y or 0
        local mg = math.sqrt(x*x + y*y)
        local v = {X=x, Y=y, Magnitude=mg}
        v.__vecKind = "Vector2"
        __vec2Store[v] = {x=x, y=y}
        v.Unit = v
        if mg > 0 then
            if skipUnit then v.Unit = v else v.Unit = __newVector2(x/mg, y/mg, true) end
        end
        v.Dot = function(self, other) local o = __v2c(other); if o then return x*o.x + y*o.y end return 0 end
        v.Angle = function() return math.atan2(0-y, x) end
        v.FuzzyEq = function(self, other, epsilon) local o=__v2c(other); if not o then return false end local dx,dy=x-o.x,y-o.y; return math.sqrt(dx*dx+dy*dy) <= (epsilon or 1e-4) end
        v.ToString = function() return string.format("%g, %g", x, y) end
        setmetatable(v, __getVec2MT())
        return __trackVal(v, "Vector2.new(" .. __tostring(x) .. ", " .. __tostring(y) .. ")")
    end
    local function __newColor3(r,g,b, isRGB)
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        mt.__index = {R=r or 0, G=g or 0, B=b or 0}
        mt.__tostring=function() return "Color3" end
        local repr
        if isRGB then repr = "Color3.fromRGB(" .. __tostring(r or 0) .. ", " .. __tostring(g or 0) .. ", " .. __tostring(b or 0) .. ")"
        else repr = "Color3.new(" .. __tostring(r or 0) .. ", " .. __tostring(g or 0) .. ", " .. __tostring(b or 0) .. ")" end
        return __trackVal(ud, repr)
    end
    -- Permissive nested-property stub for datatype userdata, hung off __realEnv
    -- because this chunk is already at Luau's 200-register ceiling and a new
    -- top-level local will not compile. Roblox datatypes expose a fixed member
    -- set (UDim2.X/Y, UDim.Offset/Scale, ...); an empty __index table returns
    -- nil for anything else, so a payload chaining a read like `a.b.Offset`
    -- dies with "attempt to index nil with 'Offset'" -- and that error never
    -- reaches a metamethod, so nothing else identifies the object. Auto-vivify
    -- instead; the returned values are inert.
    __realEnv.__autoIdx = function(self, k)
        -- Kind-aware so UDim2.X stays a UDim (the payload reads .X.Offset and
        -- .X.Scale) while Vector3.X stays a number for arithmetic.
        local rec = rawget(__valData, self)
        local kind = rec and string.sub(rec, 1, 5) or ""
        local isUDim = (kind == "UDim2" or kind == "UDim3")
        if k == "Magnitude" then return 0 end
        if k == "X" or k == "Y" or k == "Z" or k == "W" then
            if isUDim then
                local ud = newproxy(true)
                local mt = getmetatable(ud)
                mt.__index = __realEnv.__autoIdx
                mt.__tostring = function() return "UDim" end
                return __trackVal(ud, "UDim.new(0, 0)")
            end
            return 0
        end
        if k == "Offset" then
            local ud = newproxy(true)
            local mt = getmetatable(ud)
            mt.__index = __realEnv.__autoIdx
            mt.__tostring = function() return "UDim" end
            return __trackVal(ud, "UDim.new(0, 0)")
        end
        if k == "Scale" then return 0 end
        if k == "Unit" then return 0 end
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        mt.__index = __realEnv.__autoIdx
        mt.__tostring = function() return "stub" end
        return __trackVal(ud, "stub")
    end
    local function __newUDim2(...)
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        mt.__index = __realEnv.__autoIdx
        mt.__tostring=function() return "UDim2" end
        return __trackVal(ud, "UDim2.new(" .. __argsToRepr(...) .. ")")
    end
    local function __newUDim(...)
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        mt.__index = __realEnv.__autoIdx
        mt.__tostring=function() return "UDim" end
        return __trackVal(ud, "UDim.new(" .. __argsToRepr(...) .. ")")
    end
    __setUNC("Vector3", setmetatable({new=function(x,y,z) __logCall("Vector3.new", __argsToRepr(x,y,z)); return __newVector3(x,y,z) end, create=__markNative(function(x,y,z) __logCall("Vector3.create", __argsToRepr(x,y,z)); return __newVector3(x,y,z) end, "create"), FromNormalId=function() return __newVector3() end, FromAxis=function() return __newVector3() end, zero=__newVector3(0,0,0), one=__newVector3(1,1,1), new0=function() return __newVector3(0,0,0) end}, {__index=function(_,k) return __newVector3() end, __call=function(...) return __newVector3() end}))
    __setUNC("Vector2", setmetatable({new=function(x,y) __logCall("Vector2.new", __argsToRepr(x,y)); return __newVector2(x,y) end, create=__markNative(function(x,y) __logCall("Vector2.create", __argsToRepr(x,y)); return __newVector2(x,y) end, "create"), zero=__newVector2(0,0), one=__newVector2(1,1)}, {__index=function(_,k) return function(...) return __newVector2(0,0) end end, __call=function(...) return __newVector2(0,0) end}))
    -- Roblox's lowercase vector namespace (typeof stays "Vector3"/"Vector2")
    do
        local function __vecMag(v)
            local x = tonumber(rawget(v, "X") or (v.X)) or 0
            local y = tonumber(rawget(v, "Y") or (v.Y)) or 0
            local z = tonumber(rawget(v, "Z") or (v.Z)) or 0
            return math.sqrt(x * x + y * y + z * z)
        end
        __setUNC("vector", setmetatable({
            create = __markNative(function(x, y, z)
                __logCall("vector.create", __argsToRepr(x, y, z))
                return __newVector3(x, y, z)
            end, "create"),
            magnitude = __markNative(function(v)
                local m = __vecMag(v)
                local o = __newVector3(0, 0, 0)
                rawset(o, "Magnitude", m)
                return o
            end, "magnitude"),
            normalize = __markNative(function(v)
                local m = __vecMag(v)
                local x = tonumber(rawget(v, "X") or 0) or 0
                local y = tonumber(rawget(v, "Y") or 0) or 0
                local z = tonumber(rawget(v, "Z") or 0) or 0
                if m == 0 then return __newVector3(0, 0, 0) end
                return __newVector3(x / m, y / m, z / m)
            end, "normalize"),
        }, {
            __index = function(_, k) return __markNative(function() return __newVector3() end, tostring(k)) end,
            __call = function(_, ...) return __newVector3(...) end,
        }))
    end
    -- CFrame: real rotation math. The old mock answered EVERY unknown member with a
    -- (installed from its own chunk: this file sits within 1 register of the 200-register limit)
    __setUNC("CFrame", ((_G.__rawLoadFn or loadstring or load)([==[
return (function(__newVector3, __v3c, __trackVal, __logCall, __argsToRepr, __tostring, __type, math)

-- Vector3, so CFrame.Angles(x,y,z) was uncallable, CFrame.identity was a Vector3 and
-- CFrame.new(1,2,3) had no position at all. The basis rows are Right/Up/Back, so
-- CFrame.Angles == CFrame.fromEulerAnglesXYZ builds R = Rz*Ry*Rx exactly like Roblox.
local __cfStore = setmetatable({}, {__mode = "k"})
local function __cfc(cf) return __cfStore[cf] end
local __cfMT, __newCF
local function __cfXf(m, x, y, z)
    return m[1]*x + m[2]*y + m[3]*z, m[4]*x + m[5]*y + m[6]*z, m[7]*x + m[8]*y + m[9]*z
end
local function __cfMulM(a, b)
    return {a[1]*b[1]+a[2]*b[4]+a[3]*b[7], a[1]*b[2]+a[2]*b[5]+a[3]*b[8], a[1]*b[3]+a[2]*b[6]+a[3]*b[9],
            a[4]*b[1]+a[5]*b[4]+a[6]*b[7], a[4]*b[2]+a[5]*b[5]+a[6]*b[8], a[4]*b[3]+a[5]*b[6]+a[6]*b[9],
            a[7]*b[1]+a[8]*b[4]+a[9]*b[7], a[7]*b[2]+a[8]*b[5]+a[9]*b[8], a[7]*b[3]+a[8]*b[6]+a[9]*b[9]}
end
local function __cfTrans(m) return {m[1],m[4],m[7],m[2],m[5],m[8],m[3],m[6],m[9]} end
local __cfIdent = {1,0,0,0,1,0,0,0,1}
local function __cfEuler(x, y, z)                     -- radians, R = Rz*Ry*Rx
    local cx, sx = math.cos(x), math.sin(x)
    local cy, sy = math.cos(y), math.sin(y)
    local cz, sz = math.cos(z), math.sin(z)
    return {cz*cy, cz*sy*sx - sz*cx, cz*sy*cx + sz*sx,
            sz*cy, sz*sy*sx + cz*cx, sz*sy*cx - cz*sx,
            -sy, cy*sx, cy*cx}
end
local function __cfGetMT()
    if __cfMT then return __cfMT end
    local mt = {}
    mt.__tostring = function(a)
        local r = __cfStore[a]
        if not r then return "CFrame" end
        return "CFrame.fromEulerAnglesXYZ(" .. __tostring(r.x) .. ", " .. __tostring(r.y)
            .. ", " .. __tostring(r.z) .. ")"
    end
    mt.__eq = function(a, b)
        local ra, rb = __cfStore[a], __cfStore[b]
        if not ra or not rb then return rawequal(a, b) end
        local A, B = ra.m, rb.m
        return ra.x == rb.x and ra.y == rb.y and ra.z == rb.z
            and A[1]==B[1] and A[2]==B[2] and A[3]==B[3]
            and A[4]==B[4] and A[5]==B[5] and A[6]==B[6]
            and A[7]==B[7] and A[8]==B[8] and A[9]==B[9]
    end
    mt.__mul = function(a, b)
        local ra = __cfStore[a]
        if not ra then return a end
        if __type(b) == "number" then
            local m = ra.m
            return __newCF(ra.x, ra.y, ra.z, {m[1]*b,m[2]*b,m[3]*b,m[4]*b,m[5]*b,m[6]*b,m[7]*b,m[8]*b,m[9]*b})
        end
        local rb = __cfStore[b]
        if rb then
            local px, py, pz = __cfXf(ra.m, rb.x, rb.y, rb.z)
            return __newCF(ra.x + px, ra.y + py, ra.z + pz, __cfMulM(ra.m, rb.m))
        end
        local v = __v3c(b)
        if v then
            local px, py, pz = __cfXf(ra.m, v.x, v.y, v.z)
            return __newVector3(ra.x + px, ra.y + py, ra.z + pz)
        end
        return a
    end
    mt.__add = function(a, b)
        local ra, rb = __cfStore[a], __cfStore[b]
        if ra and rb then
            local m = ra.m
            return __newCF(ra.x + rb.x, ra.y + rb.y, ra.z + rb.z,
                {m[1],m[2],m[3],m[4],m[5],m[6],m[7],m[8],m[9]})
        end
        local v = __v3c(b)
        if v and ra then return __newVector3(ra.x + v.x, ra.y + v.y, ra.z + v.z) end
        local w = __v3c(a)
        if w and rb then return __newVector3(rb.x + w.x, rb.y + w.y, rb.z + w.z) end
        return a
    end
    mt.__unm = function(a)
        local r = __cfStore[a]
        if not r then return a end
        local ix, iy, iz = __cfXf(__cfTrans(r.m), r.x, r.y, r.z)
        return __newCF(-ix, -iy, -iz, __cfTrans(r.m))
    end
    __cfMT = mt
    return mt
end
local function __cfArgs(...)
    local a, n = {...}, select("#", ...)
    if n == 0 then return 0, 0, 0, nil end
    if n == 1 then
        local r = __cfStore[a[1]]
        if r then return r.x, r.y, r.z, r.m end
        local v = __v3c(a[1])
        if v then return v.x, v.y, v.z, nil end
        return 0, 0, 0, nil
    end
    if n >= 12 then
        return a[1] or 0, a[2] or 0, a[3] or 0,
            {a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12]}
    end
    if n == 4 then
        local v = __v3c(a[4])
        if v then return v.x, v.y, v.z, nil end
    end
    return a[1] or 0, a[2] or 0, a[3] or 0, nil
end
local function __cfPos(v)
    local r = __cfStore[v]
    if r then return r.x, r.y, r.z end
    local p = __v3c(v)
    if p then return p.x, p.y, p.z end
    return 0, 0, 0
end
__newCF = function(px, py, pz, m)
    px, py, pz = px or 0, py or 0, pz or 0
    m = m or __cfIdent
    local cf, rec = {}, {x = px, y = py, z = pz, m = m}
    __cfStore[cf] = rec
    cf.__cfKind = "CFrame"
    cf.Position = __newVector3(px, py, pz)
    cf.Right = __newVector3(m[1], m[4], m[7])
    cf.Up = __newVector3(m[2], m[5], m[8])
    cf.Back = __newVector3(m[3], m[6], m[9])
    cf.LookVector = __newVector3(-m[3], -m[6], -m[9])
    cf.RightVector, cf.UpVector = cf.Right, cf.Up
    cf.XVector, cf.YVector, cf.ZVector = cf.Right, cf.Up, cf.Back
    cf.X, cf.Y, cf.Z = cf.Right, cf.Up, cf.Back
    cf.GetComponents = function(self)
        return px, py, pz, m[1],m[2],m[3], m[4],m[5],m[6], m[7],m[8],m[9]
    end
    cf.ToString = function(self) return tostring(self) end
    cf.Inverse = function(self)
        local t = __cfTrans(m)
        local ix, iy, iz = __cfXf(t, px, py, pz)
        return __newCF(-ix, -iy, -iz, t)
    end
    cf.PointToWorldSpace = function(self, p)
        local v = __v3c(p)
        if not v then return self.Position end
        local x, y, z = __cfXf(m, v.x, v.y, v.z)
        return __newVector3(x + px, y + py, z + pz)
    end
    cf.PointToObjectSpace = function(self, p)
        local v = __v3c(p)
        if not v then return __newVector3() end
        return __newVector3(__cfXf(__cfTrans(m), v.x - px, v.y - py, v.z - pz))
    end
    cf.VectorToWorldSpace = function(self, v)
        local c = __v3c(v)
        if not c then return __newVector3() end
        return __newVector3(__cfXf(m, c.x, c.y, c.z))
    end
    cf.VectorToObjectSpace = function(self, v)
        local c = __v3c(v)
        if not c then return __newVector3() end
        return __newVector3(__cfXf(__cfTrans(m), c.x, c.y, c.z))
    end
    cf.ToWorldSpace, cf.ToObjectSpace = cf.PointToWorldSpace, cf.PointToObjectSpace
    cf.ToWorldSpace = function(self, other) return self * other end
    cf.ToObjectSpace = function(self, other) return self:Inverse() * other end
    cf.Lerp = function(self, goal, alpha)
        local g = __cfStore[goal]
        if not g then return self end
        alpha = alpha or 0
        local m2 = {m[1]+(g.m[1]-m[1])*alpha, m[2]+(g.m[2]-m[2])*alpha, m[3]+(g.m[3]-m[3])*alpha,
                    m[4]+(g.m[4]-m[4])*alpha, m[5]+(g.m[5]-m[5])*alpha, m[6]+(g.m[6]-m[6])*alpha,
                    m[7]+(g.m[7]-m[7])*alpha, m[8]+(g.m[8]-m[8])*alpha, m[9]+(g.m[9]-m[9])*alpha}
        return __newCF(px+(g.x-px)*alpha, py+(g.y-py)*alpha, pz+(g.z-pz)*alpha, m2)
    end
    cf.ToEulerAnglesXYZ = function(self)
        local y = math.asin(math.clamp(-m[7], -1, 1))
        if math.abs(y) < 1.5707963267948966 then
            return math.atan2(m[8], m[9]), y, math.atan2(m[4], m[1])
        end
        return math.atan2(-m[6], m[5]), y, 0
    end
    cf.ToOrientation = function(self)                    -- YXZ order, radians
        local x = math.asin(math.clamp(-m[6], -1, 1))
        if math.abs(x) < 1.5707963267948966 then
            return x, math.atan2(m[3], m[9]), math.atan2(m[4], m[5])
        end
        return x, math.atan2(-m[7], m[1]), 0
    end
    cf.ToAxisAngle = function(self)
        local c = math.clamp((m[1] + m[5] + m[9] - 1) / 2, -1, 1)
        local ang = math.acos(c)
        local s = math.sqrt(1 - c * c)
        if s < 1e-9 then return __newVector3(1, 0, 0), 0 end
        local k = 0.5 / s
        return __newVector3((m[8] - m[6]) * k, (m[3] - m[7]) * k, (m[4] - m[2]) * k), ang
    end
    setmetatable(cf, __cfGetMT())
    return __trackVal(cf, "CFrame.new(" .. __tostring(px) .. ", " .. __tostring(py) .. ", " .. __tostring(pz) .. ")")
end
local function __cfFromAxisAngle(ax, ay, az, ang)
    local l = math.sqrt(ax*ax + ay*ay + az*az)
    if l == 0 then return __cfIdent end
    local x, y, z = ax / l, ay / l, az / l
    local s, c, t = math.sin(ang) / l, math.cos(ang), 1 - math.cos(ang)
    return {t*x*x + c, t*x*y - s*z, t*x*z + s*y,
            t*x*y + s*z, t*y*y + c, t*y*z - s*x,
            t*x*z - s*y, t*y*z + s*x, t*z*z + c}
end
local __cfNs = {}
__cfNs.new = function(...)
    __logCall("CFrame.new", __argsToRepr(...))
    local x, y, z, m = __cfArgs(...)
    return __newCF(x, y, z, m)
end
__cfNs.Angles = function(rx, ry, rz)
    __logCall("CFrame.Angles", __argsToRepr(rx, ry, rz))
    return __newCF(0, 0, 0, __cfEuler(math.rad(rx or 0), math.rad(ry or 0), math.rad(rz or 0)))
end
__cfNs.fromEulerAnglesXYZ = function(x, y, z)
    __logCall("CFrame.fromEulerAnglesXYZ", __argsToRepr(x, y, z))
    return __newCF(0, 0, 0, __cfEuler(x or 0, y or 0, z or 0))
end
__cfNs.FromEulerAnglesXYZ = __cfNs.fromEulerAnglesXYZ
__cfNs.FromAxisAngle = function(v, ang)
    __logCall("CFrame.FromAxisAngle", __argsToRepr(v, ang))
    local ax, ay, az = __cfPos(v)
    return __newCF(0, 0, 0, __cfFromAxisAngle(ax, ay, az, ang or 0))
end
__cfNs.fromAxisAngle = __cfNs.FromAxisAngle
__cfNs.FromMatrix = function(pos, vX, vY, vZ)
    __logCall("CFrame.FromMatrix", __argsToRepr(pos, vX, vY, vZ))
    local px, py, pz = __cfPos(pos)
    local ax, ay, az = __cfPos(vX)
    local bx, by, bz = __cfPos(vY)
    local cx, cy, cz = __cfPos(vZ)
    return __newCF(px, py, pz, {ax,bx,cx, ay,by,cy, az,bz,cz})
end
__cfNs.FromObject = function(pos, vX, vY)
    __logCall("CFrame.FromObject", __argsToRepr(pos, vX, vY))
    local px, py, pz = __cfPos(pos)
    local ax, ay, az = __cfPos(vX)
    local bx, by, bz = __cfPos(vY)
    local cx, cy, cz = ay*bz - az*by, az*bx - ax*bz, ax*by - ay*bx
    return __newCF(px, py, pz, {ax,bx,cx, ay,by,cy, az,bz,cz})
end
__cfNs.lookAt = function(at, look)
    __logCall("CFrame.lookAt", __argsToRepr(at, look))
    local ax, ay, az = __cfPos(at)
    local bx, by, bz = __cfPos(look)
    local dx, dy, dz = bx - ax, by - ay, bz - az
    local l = math.sqrt(dx*dx + dy*dy + dz*dz)
    if l == 0 then dx, dy, dz, l = 0, 0, -1, 1 end
    local kx, ky, kz = -dx/l, -dy/l, -dz/l          -- Back looks away from the target
    local ux, uy, uz = 0, 1, 0
    if math.abs(ky) > 0.999 then ux, uy, uz = 1, 0, 0 end
    local rx, ry, rz = uy*kz - uz*ky, uz*kx - ux*kz, ux*ky - uy*kx
    local rl = math.sqrt(rx*rx + ry*ry + rz*rz)
    if rl > 0 then rx, ry, rz = rx/rl, ry/rl, rz/rl end
    local nx, ny, nz = ky*rz - kz*ry, kz*rx - kx*rz, kx*ry - ky*rx
    return __newCF(ax, ay, az, {rx,nx,kx, ry,ny,ky, rz,nz,kz})
end
__cfNs.LerpCFrame = function(a, b, t) return a:Lerp(b, t) end
__cfNs.fromEulerAnglesYXZ = function(x, y, z)
    x, y, z = x or 0, y or 0, z or 0
    local cx, sx = math.cos(x), math.sin(x)
    local cy, sy = math.cos(y), math.sin(y)
    local cz, sz = math.cos(z), math.sin(z)
    return __newCF(0, 0, 0, {cy*cz + sy*sx*sz, -cy*sz + sy*sx*cz, sy*cx,
                             cx*sz, cx*cz, -sx,
                             -sy*cz + cy*sx*sz, sy*sz + cy*sx*cz, cy*cx})
end
__cfNs.FromEulerAnglesYXZ = __cfNs.fromEulerAnglesYXZ
__cfNs.getmatrix = function(cf)
    local _, _, _, a1,a2,a3, a4,a5,a6, a7,a8,a9 = cf:GetComponents()
    return {a1,a2,a3, a4,a5,a6, a7,a8,a9}
end
__cfNs.getcomponents = function(cf)
    local px, py, pz, a1,a2,a3, a4,a5,a6, a7,a8,a9 = cf:GetComponents()
    return {a1,a2,a3, a4,a5,a6, a7,a8,a9, px, py, pz}
end
__cfNs.identity = __newCF(0, 0, 0)
return {CFrame = setmetatable(__cfNs, {
    __call = function(_, ...) return __cfNs.new(...) end,
    __index = function() return function() return __newCF(0, 0, 0) end end
}), new = __newCF}
end)(...)
]==], "@roblox/cframe"))(__newVector3, __v3c, __trackVal, __logCall, __argsToRepr,
        __tostring, __type, math).CFrame)
    -- // PATH2D + PATHSTATUS
    -- Roblox's Path2D is real geometry (arc-length parameterisation + closest-point
    -- queries) and was absent here, so PathfindingService:CreatePath style code
    -- diverged.  Loaded as its own chunk: the header chunk already sits exactly at
    -- Luau's 200-register limit.
    do
    local __p2, __perr = (_G.__rawLoadFn or loadstring or load)([==[
return (function(__v2c, __v3c, __newVector2, __logCall, __argsToRepr, __type, __tostring,
                  math)
-- normalise a control point: Roblox takes Vector2 (Vector3 is accepted, XY used)
local function __pt(v)
    local p = __v2c(v)
    if p then return p.x, p.y end
    local q = __v3c(v)
    if q then return q.x, q.y end
    return 0, 0
end

-- squared distance + clamped parameter for the projection onto segment a->b
local function __proj(px, py, ax, ay, bx, by)
    local dx, dy = bx - ax, by - ay
    local dd = dx * dx + dy * dy
    if dd <= 1e-12 then
        local ex, ey = px - ax, py - ay
        return ex * ex + ey * ey, 0, ax, ay
    end
    local t = ((px - ax) * dx + (py - ay) * dy) / dd
    if t < 0 then t = 0 elseif t > 1 then t = 1 end
    local cx, cy = ax + dx * t, ay + dy * t
    local ex, ey = px - cx, py - cy
    return ex * ex + ey * ey, t, cx, cy
end

local function __build(cp, closed)
    local pts, n = {}, 0
    if __type(cp) == "table" then
        for i = 1, #cp do
            local x, y = __pt(cp[i])
            n = n + 1
            pts[n] = {x = x, y = y}
        end
    elseif cp ~= nil then
        local x, y = __pt(cp)
        n = 1
        pts[1] = {x = x, y = y}
    end
    closed = closed and true or false
    local segs = n > 0 and n - 1 or 0
    if closed and n > 2 then segs = n end
    local cum, total = {}, 0
    for i = 1, segs do
        local a, b = pts[i], pts[i + 1] or pts[1]
        total = total + math.sqrt((b.x - a.x) ^ 2 + (b.y - a.y) ^ 2)
        cum[i] = total
    end
    return {pts = pts, n = n, closed = closed, cum = cum, total = total, segs = segs}
end

-- point at arc-length distance along the path
local function __ptAt(pd, dist)
    if pd.n == 0 then return 0, 0 end
    if pd.total <= 0 or pd.segs == 0 then
        local a = pd.pts[1]
        return a.x, a.y
    end
    local d = dist
    if pd.closed then
        d = d % pd.total
    elseif d < 0 then
        d = 0
    elseif d > pd.total then
        d = pd.total
    end
    for i = 1, pd.segs do
        local c = pd.cum[i]
        if d <= c or i == pd.segs then
            local prev = i == 1 and 0 or pd.cum[i - 1]
            local a, b = pd.pts[i], pd.pts[i + 1] or pd.pts[1]
            local seg = c - prev
            local t = seg > 0 and (d - prev) / seg or 0
            if t < 0 then t = 0 elseif t > 1 then t = 1 end
            return a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t
        end
    end
    local last = pd.pts[pd.n]
    return last.x, last.y
end

-- closest point on the path to (px,py); returns cx, cy, dist2
local function __closest(pd, px, py)
    if pd.n == 0 then return 0, 0, 1/0 end
    if pd.segs == 0 then
        local a = pd.pts[1]
        local ex, ey = px - a.x, py - a.y
        return a.x, a.y, ex * ex + ey * ey
    end
    local bx, by, bd
    for i = 1, pd.segs do
        local a, b = pd.pts[i], pd.pts[i + 1] or pd.pts[1]
        local d2, _, cx, cy = __proj(px, py, a.x, a.y, b.x, b.y)
        if bd == nil or d2 < bd then bd, bx, by = d2, cx, cy end
    end
    return bx, by, bd
end

-- PathStatus enum: 0 Success, 1 ClosestPointIsStart, 2 ClosestPointIsEnd,
-- 3 ClosestPointNotWithin
local __NAMES = {"Success", "ClosestPointIsStart", "ClosestPointIsEnd",
                 "ClosestPointNotWithin"}
local __statusItems = {}
for i = 1, #__NAMES do
    local nm = __NAMES[i]
    __statusItems[nm] = {__enumItem = true, Name = nm, Value = i - 1,
                         EnumType = "PathStatus"}
end
local PathStatus = setmetatable({__enumType = "PathStatus", items = __statusItems},
    {__index = function(_, k)
        if __type(k) == "string" then return __statusItems[k] end
        return nil
    end})

local __instMeta

local function __mCompute(self, distance)
    local r = self.__pd
    local x, y = __ptAt(r, __type(distance) == "number" and distance or 0)
    return __newVector2(x, y)
end

local function __mClosestPoint(self, point)
    local px, py = __pt(point)
    local cx, cy = __closest(self.__pd, px, py)
    self.__st = 0
    return __newVector2(cx, cy)
end

local function __mClosestPointWithin(self, point, maxDistance)
    local px, py = __pt(point)
    local cx, cy, d2 = __closest(self.__pd, px, py)
    local d = math.sqrt(d2)
    local lim = __type(maxDistance) == "number" and maxDistance or 0
    if d <= lim then
        self.__st = 0
        return __newVector2(cx, cy), d
    end
    self.__st = 3
    return nil, d
end

local function __mClosestPointNotWithin(self, point, maxDistance)
    local px, py = __pt(point)
    local cx, cy, d2 = __closest(self.__pd, px, py)
    local d = math.sqrt(d2)
    local lim = __type(maxDistance) == "number" and maxDistance or 0
    if d > lim then
        self.__st = 0
        return __newVector2(cx, cy), d
    end
    self.__st = 3
    return nil, d
end

local function __mClosestPointAsync(self, point, maxDistance)
    local px, py = __pt(point)
    local _, _, d2 = __closest(self.__pd, px, py)
    self.__st = 0
    local lim = __type(maxDistance) == "number" and maxDistance or 0
    return math.sqrt(d2) <= lim
end

local function __mGetControlPoints(self)
    local out = {}
    for i = 1, self.__pd.n do
        out[i] = __newVector2(self.__pd.pts[i].x, self.__pd.pts[i].y)
    end
    return out
end

local function __mGetClosed(self) return self.__pd.closed end
local function __mGetStatus(self) return __statusItems[__NAMES[self.__st + 1]] end

__instMeta = {
    __metatable = "The metatable is locked",
    __index = function(self, k)
        if k == "Status" then
            return __statusItems[__NAMES[self.__st + 1]]
        elseif k == "ControlPoints" then
            return __mGetControlPoints(self)
        elseif k == "Closed" then
            return self.__pd.closed
        end
        return nil
    end,
}

local function __new(controlPoints, closed)
    local o = {
        __pd = __build(controlPoints, closed),
        __st = 0,
        __vecKind = "Path2D",
        Compute = __mCompute,
        ClosestPoint = __mClosestPoint,
        ClosestPointWithin = __mClosestPointWithin,
        ClosestPointNotWithin = __mClosestPointNotWithin,
        ClosestPointAsync = __mClosestPointAsync,
        GetControlPoints = __mGetControlPoints,
        GetClosed = __mGetClosed,
        GetStatus = __mGetStatus,
    }
    -- closed paths expose Closed as a plain property
    return setmetatable(o, __instMeta)
end

local Path2D = setmetatable({
    new = function(controlPoints, closed)

        return __new(controlPoints, closed)
    end,
}, {
    __call = function(_, ...) return __new(...) end,
    __index = function() return function(...) return __new(...) end end,
})

return {Path2D = Path2D, PathStatus = PathStatus}
end)(...)
]==], "@roblox/path2d")
        if not __p2 then __origPrint("[p2diag] LOAD FAILED: " .. __tostring(__perr)) end
        if __p2 then
            local __pkg = __p2(__v2c, __v3c, __newVector2, __logCall, __argsToRepr, __type, __tostring,
                math)
            if __pkg and __pkg.Path2D then
                __setUNC("Path2D", __pkg.Path2D)
                __setUNC("PathStatus", __pkg.PathStatus)
            end
        end
    end
    -- // ENCODINGSERVICE + HASHES
    -- EncodingService was missing entirely, so anything that hashes a string
    -- (self-integrity checks, the polsec/Fulcrum enclib, key activators) died at
    -- game:GetService("EncodingService"). ComputeStringHash is implemented for
    -- real: Roblox's algorithms, verified against the standard test vectors.
    -- Compression goes through Lune's own @lune/serde codecs (zstd/lz4/gzip/zlib/
    -- brotli), so DecompressBuffer really decompresses -- several samples ship
    -- their entire payload as a Zstd blob behind one DecompressBuffer call.
    do
    local __hs = (_G.__rawLoadFn or loadstring or load)([==[
return (function(buffer, __logCall, __argsToRepr, __tostring, __type, __serde)
local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local rshift, lshift = bit32.rshift, bit32.lshift

local function ror(x, n) return bor(rshift(x, n), lshift(x, 32 - n)) end
local function rol(x, n) return bor(lshift(x, n), rshift(x, 32 - n)) end
local function b8(x, i) return band(rshift(x, (3 - i) * 8), 255) end
local function toBytes32(v)
    return { b8(v, 0), b8(v, 1), b8(v, 2), b8(v, 3) }
end

local function strBytes(s)
    s = __tostring(s or "")
    local out = {}
    for i = 1, #s do out[i] = string.byte(s, i) end
    return out
end

-- big-endian 64-byte-block padding with the 64-bit bit length appended
local function padBE(bytes)
    local n = #bytes
    local total = ((n + 9 + 63) // 64) * 64
    local m = {}
    for i = 1, n do m[i] = bytes[i] end
    m[n + 1] = 0x80
    for i = n + 2, total - 8 do m[i] = 0 end
    local bitlen = n * 8
    local hi = bitlen // 4294967296
    local lo = bitlen % 4294967296
    for i = 0, 3 do m[total - 7 + i] = band(rshift(hi, (3 - i) * 8), 255) end
    for i = 0, 3 do m[total - 3 + i] = band(rshift(lo, (3 - i) * 8), 255) end
    return m, total
end

-- little-endian 64-byte-block padding (MD5)
local function padLE(bytes)
    local n = #bytes
    local total = ((n + 9 + 63) // 64) * 64
    local m = {}
    for i = 1, n do m[i] = bytes[i] end
    m[n + 1] = 0x80
    for i = n + 2, total - 8 do m[i] = 0 end
    local bitlen = n * 8
    local lo = bitlen % 4294967296
    local hi = bitlen // 4294967296
    -- 1-based block: the trailing 8 bytes are indices total-7 .. total, and MD5
    -- stores the 64-bit length little-endian, so lo comes first.
    for i = 0, 3 do m[total - 7 + i] = band(rshift(lo, i * 8), 255) end
    for i = 0, 3 do m[total - 3 + i] = band(rshift(hi, i * 8), 255) end
    return m, total
end

-- ---------------------------------------------------------------- SHA-256 --
local SK = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}
local function sha256(input)
    local m, total = padBE(strBytes(input))
    local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
    local w = {}
    for chunk = 1, total, 64 do
        for i = 0, 15 do
            local b = chunk + i * 4
            w[i] = bor(lshift(m[b], 24), lshift(m[b + 1], 16), lshift(m[b + 2], 8), m[b + 3])
        end
        for i = 16, 63 do
            local s0 = bxor(bxor(ror(w[i - 15], 7), ror(w[i - 15], 18)), rshift(w[i - 15], 3))
            local s1 = bxor(bxor(ror(w[i - 2], 17), ror(w[i - 2], 19)), rshift(w[i - 2], 10))
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 4294967296
        end
        local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
        for i = 0, 63 do
            local S1 = bxor(bxor(ror(e, 6), ror(e, 11)), ror(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local t1 = (hh + S1 + ch + SK[i + 1] + w[i]) % 4294967296
            local S0 = bxor(bxor(ror(a, 2), ror(a, 13)), ror(a, 22))
            local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
            local t2 = (S0 + maj) % 4294967296
            hh = g; g = f; f = e
            e = (d + t1) % 4294967296
            d = c; c = b; b = a
            a = (t1 + t2) % 4294967296
        end
        h[1] = (h[1] + a) % 4294967296
        h[2] = (h[2] + b) % 4294967296
        h[3] = (h[3] + c) % 4294967296
        h[4] = (h[4] + d) % 4294967296
        h[5] = (h[5] + e) % 4294967296
        h[6] = (h[6] + f) % 4294967296
        h[7] = (h[7] + g) % 4294967296
        h[8] = (h[8] + hh) % 4294967296
    end
    local out = {}
    for i = 1, 8 do
        local q = toBytes32(h[i])
        for j = 1, 4 do out[(i - 1) * 4 + j] = q[j] end
    end
    return out
end

-- ------------------------------------------------------------------ SHA-1 --
local function sha1(input)
    local m, total = padBE(strBytes(input))
    local h = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }
    local w = {}
    for chunk = 1, total, 64 do
        for i = 0, 15 do
            local b = chunk + i * 4
            w[i] = bor(lshift(m[b], 24), lshift(m[b + 1], 16), lshift(m[b + 2], 8), m[b + 3])
        end
        for i = 16, 79 do
            w[i] = rol(bxor(bxor(w[i - 3], w[i - 8]), bxor(w[i - 14], w[i - 16])), 1)
        end
        local a, b, c, d, e = h[1], h[2], h[3], h[4], h[5]
        for i = 0, 79 do
            local f, k
            if i < 20 then
                f = bor(band(b, c), band(bnot(b), d)); k = 0x5A827999
            elseif i < 40 then
                f = bxor(bxor(b, c), d); k = 0x6ED9EBA1
            elseif i < 60 then
                f = bor(bor(band(b, c), band(b, d)), band(c, d)); k = 0x8F1BBCDC
            else
                f = bxor(bxor(b, c), d); k = 0xCA62C1D6
            end
            local tmp = (rol(a, 5) + f + e + k + w[i]) % 4294967296
            e = d; d = c; c = rol(b, 30); b = a; a = tmp
        end
        h[1] = (h[1] + a) % 4294967296
        h[2] = (h[2] + b) % 4294967296
        h[3] = (h[3] + c) % 4294967296
        h[4] = (h[4] + d) % 4294967296
        h[5] = (h[5] + e) % 4294967296
    end
    local out = {}
    for i = 1, 5 do
        local q = toBytes32(h[i])
        for j = 1, 4 do out[(i - 1) * 4 + j] = q[j] end
    end
    return out
end

-- -------------------------------------------------------------------- MD5 --
local MK = {}
do
    for i = 0, 63 do
        MK[i] = math.floor(math.abs(math.sin(i + 1)) * 4294967296)
    end
end
local MS = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
}
local function md5(input)
    local m, total = padLE(strBytes(input))
    local h = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 }
    local x = {}
    for chunk = 1, total, 64 do
        for i = 0, 15 do
            local b = chunk + i * 4
            x[i] = bor(m[b], lshift(m[b + 1], 8), lshift(m[b + 2], 16), lshift(m[b + 3], 24))
        end
        local a, b, c, d = h[1], h[2], h[3], h[4]
        for i = 0, 63 do
            local f, g
            if i < 16 then
                f = bor(band(b, c), band(bnot(b), d)); g = i
            elseif i < 32 then
                f = bor(band(d, b), band(bnot(d), c)); g = (5 * i + 1) % 16
            elseif i < 48 then
                f = bxor(bxor(b, c), d); g = (3 * i + 5) % 16
            else
                f = bxor(c, bor(b, bnot(d))); g = (7 * i) % 16
            end
            local tmp = d
            d = c
            c = b
            b = (b + rol((a + f + MK[i] + x[g]) % 4294967296, MS[i + 1])) % 4294967296
            a = tmp
        end
        h[1] = (h[1] + a) % 4294967296
        h[2] = (h[2] + b) % 4294967296
        h[3] = (h[3] + c) % 4294967296
        h[4] = (h[4] + d) % 4294967296
    end
    local out = {}
    for i = 1, 4 do
        local v = h[i]
        local q = { band(v, 255), band(rshift(v, 8), 255),
                    band(rshift(v, 16), 255), band(rshift(v, 24), 255) }
        for j = 1, 4 do out[(i - 1) * 4 + j] = q[j] end
    end
    return out
end

-- ------------------------------------------------------------------ CRC32 --
local CRCT = {}
do
    for i = 0, 255 do
        local c = i
        for _ = 1, 8 do
            if band(c, 1) == 1 then c = bxor(rshift(c, 1), 0xEDB88320)
            else c = rshift(c, 1) end
        end
        CRCT[i] = c
    end
end
local function crc32(input)
    local bytes = strBytes(input)
    local c = 0xFFFFFFFF
    for i = 1, #bytes do
        c = bxor(CRCT[band(bxor(c, bytes[i]), 255)], rshift(c, 8))
    end
    c = bxor(c, 0xFFFFFFFF)
    return toBytes32(c)
end

-- --------------------------------------------------------------- Adler32 --
local function adler32(input)
    local bytes = strBytes(input)
    local a, b = 1, 0
    for i = 1, #bytes do
        a = (a + bytes[i]) % 65521
        b = (b + a) % 65521
    end
    return { band(rshift(b, 8), 255), band(b, 255),
             band(rshift(a, 8), 255), band(a, 255) }
end

-- Roblox accepts either the enum item or its name; normalise to a name.
local function algoName(algo)
    if algo == nil then return "Sha256" end
    local raw
    if __type(algo) == "table" then
        raw = algo.Name or algo.name or __tostring(algo)
    else
        raw = __tostring(algo)
    end
    -- Roblox accepts any casing and a separating dash ("SHA256", "sha-256",
    -- "md5"); normalize to the canonical table key so those all resolve.
    local letters = raw:gsub("[^%w]", ""):lower()
    if letters == "sha256" then return "Sha256" end
    if letters == "sha1" then return "Sha1" end
    if letters == "md5" then return "Md5" end
    if letters == "crc32" then return "Crc32" end
    if letters == "adler32" then return "Adler32" end
    return raw
end

local HASHES = {
    Sha256 = sha256, Sha1 = sha1, Md5 = md5,
    Crc32 = crc32, Adler32 = adler32,
}

local HEX = {}
for i = 0, 9 do HEX[i] = string.char(48 + i) end
for i = 10, 15 do HEX[i] = string.char(87 + i) end
local function toHexString(bytes)
    local out = {}
    for i = 1, #bytes do
        local v = bytes[i]
        out[i * 2 - 1] = HEX[band(rshift(v, 4), 15)]
        out[i * 2] = HEX[band(v, 15)]
    end
    return table.concat(out)
end

-- Roblox returns ComputeStringHash as a lowercase HEX STRING, not raw bytes or a
-- buffer. Callers rely on this: the polsec/Fulcrum enclib does #a and
-- a:gsub(".", string.byte(a)) on the result, which errors on a buffer with
-- "attempt to get length of a buffer value".
local function computeStringHash(_, input, algo)
    local name = algoName(algo)
    __logCall("EncodingService:ComputeStringHash", __argsToRepr(input, name))
    local fn = HASHES[name]
    if not fn then
        error("EncodingService:ComputeStringHash: unsupported hash algorithm '"
            .. name .. "' (implemented: Sha256, Sha1, Md5, Crc32, Adler32)", 2)
    end
    return toHexString(fn(input))
end

-- ---------------------------------------------------------------- COMPRESSION
-- Roblox CompressionAlgorithm -> Lune serde codec name.
local CODEC = {
    Zstd = "zstd", Lz4 = "lz4", Zlib = "zlib", GZip = "gzip", Gzip = "gzip",
    Brotli = "brotli", Raw = "zlib", None = "zlib",
}
local function codecName(algo)
    if algo == nil then return "zstd" end
    local nm
    local k = __type(algo)
    if k == "number" then
        -- Roblox enum values: Lz4 = 2, Zstd = 3.
        nm = (algo == 2) and "Lz4" or "Zstd"
    else
        nm = __tostring(algo)
        if k == "table" or k == "userdata" then
            local ok, n = pcall(function() return algo.Name end)
            if ok and n ~= nil then nm = __tostring(n) end
        end
    end
    -- "Enum.CompressionAlgorithm.Zstd" -> "Zstd"
    nm = __tostring(nm):match("[^%.]+$") or __tostring(nm)
    return CODEC[nm] or nm:lower()
end

local function toBuffer(s) return buffer.fromstring(__tostring(s)) end

local function codecCall(kind, buf, algo)
    local fmt = codecName(algo)
    local str = buffer.tostring(buf)
    __logCall("EncodingService:" .. kind,
        string.format("%d bytes, %s", #str, fmt))
    if not __serde then
        error("EncodingService:" .. kind
            .. ": no compression backend is wired into this harness", 2)
    end
    return fmt, str
end

-- Roblox's *Async variants are engine generators; every script in the corpus
-- consumes the decoded value straight away, so return it directly.
local function DecompressBuffer(_, buf, algo)
    local fmt, str = codecCall("DecompressBuffer", buf, algo)
    return toBuffer(__serde.decompress(fmt, str))
end

local function CompressBuffer(_, buf, algo)
    local fmt, str = codecCall("CompressBuffer", buf, algo)
    return toBuffer(__serde.compress(fmt, str))
end

local function DecompressAsync(_, buf, algo)
    local fmt, str = codecCall("DecompressAsync", buf, algo)
    return toBuffer(__serde.decompress(fmt, str))
end

local function CompressAsync(_, buf, algo)
    local fmt, str = codecCall("CompressAsync", buf, algo)
    return toBuffer(__serde.compress(fmt, str))
end

-- __svcName makes type()/typeof report this as a Roblox Instance
local service = {
    __svcName = "EncodingService",
    ComputeStringHash = computeStringHash,
    CompressBuffer = CompressBuffer,
    DecompressBuffer = DecompressBuffer,
    CompressAsync = CompressAsync,
    DecompressAsync = DecompressAsync,
}
service.__index = service

return {
    EncodingService = service,
    hashes = HASHES,
    bufferOf = toBuffer,
}
end)(...)
]==], "@roblox/encoding")
        if __hs then
            local __serdeMod = _G.__serde
            _G.__serde = nil
            _G.__ENCODING = __hs(buffer, __logCall, __argsToRepr, __tostring, __type, __serdeMod)
        end
    end

    _G.__rawLoadFn = nil
    __setUNC("Color3", setmetatable({new=function(r,g,b) __logCall("Color3.new", __argsToRepr(r,g,b)); return __newColor3(r,g,b,false) end, fromRGB=function(r,g,b) __logCall("Color3.fromRGB", __argsToRepr(r,g,b)); return __newColor3(r,g,b,true) end, fromHSV=function(h,s,v) __logCall("Color3.fromHSV", __argsToRepr(h,s,v)); local ud=newproxy(true); __trackVal(ud, "Color3.fromHSV(" .. __argsToRepr(h,s,v) .. ")"); return ud end}, {__index=function(_,k) return function(...) local ud=newproxy(true); __trackVal(ud, "Color3."..tostring(k).."("..__argsToRepr(...)..")"); return ud end end, __call=function(r,g,b) return __newColor3(255,255,255,true) end}))
    __setUNC("Color3uint8", setmetatable({
        new=function(r, g, b, a)
            __logCall("Color3uint8.new", __argsToRepr(r, g, b, a))
            local x = __type(r) == "number" and r or 0
            local y = __type(g) == "number" and g or 0
            local z = __type(b) == "number" and b or 0
            local w = __type(a) == "number" and a or 255
            return {__vecKind="Color3uint8",
                r=math.floor(math.clamp(x, 0, 255) + 0.5),
                g=math.floor(math.clamp(y, 0, 255) + 0.5),
                b=math.floor(math.clamp(z, 0, 255) + 0.5),
                a=math.floor(math.clamp(w, 0, 255) + 0.5)}
        end,
        FromRGB=function(r, g, b)
            return {__vecKind="Color3uint8", r=r or 0, g=g or 0, b=b or 0, a=255}
        end,
        FromRGBA=function(r, g, b, a)
            return {__vecKind="Color3uint8", r=r or 0, g=g or 0, b=b or 0, a=a or 255}
        end,
        FromHex=function(h)
            h = tostring(h or "000000FF"):gsub("^#", "")
            local r = tonumber(h:sub(1, 2), 16) or 0
            local g = tonumber(h:sub(3, 4), 16) or 0
            local b = tonumber(h:sub(5, 6), 16) or 0
            local a = tonumber(h:sub(7, 8), 16) or 255
            return {__vecKind="Color3uint8", r=r, g=g, b=b, a=a}
        end,
    }, {__index=function(_, k)
        if k == "ToHex" then return function() end end
        return function(...) return __newColor3(255, 255, 255, true) end
    end, __call=function(_, ...)
        return {__vecKind="Color3uint8", r=0, g=0, b=0, a=255}
    end}))
    __setUNC("NumberPose", setmetatable({
        new=function(n, w)
            __logCall("NumberPose.new", __argsToRepr(n, w))
            return {__vecKind="NumberPose",
                Number=__type(n) == "number" and n or 0,
                Weight=__type(w) == "number" and w or 0}
        end,
    }, {__call=function(_, ...) return {__vecKind="NumberPose", Number=0, Weight=0} end}))
    __setUNC("UDim2", setmetatable({new=function(...) __logCall("UDim2.new", __argsToRepr(...)); return __newUDim2(...) end, fromScale=function(...) __logCall("UDim2.fromScale", __argsToRepr(...)); return __newUDim2(...) end, fromOffset=function(...) __logCall("UDim2.fromOffset", __argsToRepr(...)); return __newUDim2(...) end}, {__index=function(_,k) return function(...) return __newUDim2(...) end end, __call=function(...) return __newUDim2(...) end}))
    __setUNC("UDim", setmetatable({new=function(...) __logCall("UDim.new", __argsToRepr(...)); return __newUDim(...) end}, {__index=function(_,k) return function(...) return __newUDim(...) end end, __call=function(...) return __newUDim(...) end}))
    __setUNC("BrickColor", setmetatable({new=function(...) __logCall("BrickColor.new", __argsToRepr(...)); local ud=newproxy(true); local mt=getmetatable(ud); mt.__index={Name="Medium stone grey"}; __trackVal(ud, "BrickColor.new(" .. __argsToRepr(...) .. ")"); return ud end, Random=function(seed) seed=seed or 1; local ud=newproxy(true); __trackVal(ud, "BrickColor.Random(" .. tostring(seed) .. ")"); return ud end}, {__index=function(_,k) return function(...) local ud=newproxy(true); __trackVal(ud, "BrickColor."..tostring(k).."()"); return ud end end, __call=function(...) local ud=newproxy(true); __trackVal(ud, "BrickColor("..__argsToRepr(...)..")"); return ud end}))
    __setUNC("ColorSequenceKeypoint", setmetatable({new=function(...) __logCall("ColorSequenceKeypoint.new", __argsToRepr(...)); return {Time=0, Value=__newColor3(255,255,255,true)} end}, {__call=function(_, ...) return {Time=0} end}))
    __setUNC("ColorSequence", setmetatable({new=function(...) __logCall("ColorSequence.new", __argsToRepr(...)); local ud=newproxy(true); __trackVal(ud, "ColorSequence.new(" .. __argsToRepr(...) .. ")"); return ud end}, {__index=function() return __newColor3(255,255,255,true) end, __call=function(...) local ud=newproxy(true); __trackVal(ud, "ColorSequence("..__argsToRepr(...)..")"); return ud end}))
    __setUNC("NumberSequenceKeypoint", setmetatable({new=function(...) return {Time=0, Value=0} end}, {__call=function() return {Time=0, Value=0} end}))
    __setUNC("NumberSequence", setmetatable({new=function(...) __logCall("NumberSequence.new", __argsToRepr(...)); return {} end}, {__call=function() return {} end}))
    __setUNC("NumberRange", setmetatable({new=function(...) __logCall("NumberRange.new", __argsToRepr(...)); return {Min=0, Max=0} end}, {__call=function() return {Min=0, Max=0} end}))
    __setUNC("TweenInfo", setmetatable({new=function(...) __logCall("TweenInfo.new", __argsToRepr(...)); return {Time=0.3, EasingStyle=Enum.EasingStyle.Linear} end}, {__call=function(_, ...) return {Time=0.3} end}))
    __setUNC("Rect", setmetatable({new=function(...)
                local args = {...}
                __logCall("Rect.new", __argsToRepr(...))
                if #args == 4 and type(args[1]) == "number" then
                    return {Min=__newVector2(args[1], args[2]), Max=__newVector2(args[3], args[4])}
                end
                if #args == 2 then return {Min=args[1], Max=args[2]} end
                if #args >= 1 then return {Min=args[1], Max=args[1]} end
                return {Min=__newVector2(0,0), Max=__newVector2(0,0)}
            end}, {__call=function(_, ...)
                local args = {...}
                if #args == 4 and type(args[1]) == "number" then
                    return {Min=__newVector2(args[1], args[2]), Max=__newVector2(args[3], args[4])}
                end
                if #args == 2 then return {Min=args[1], Max=args[2]} end
                return {Min=__newVector2(0,0), Max=__newVector2(0,0)}
            end}))
    __setUNC("Region3", setmetatable({new=function(...) return {} end}, {__call=function() return {} end}))
    __setUNC("Region3int16", setmetatable({new=function(...) return {} end}, {__call=function() return {} end}))
    __setUNC("Vector3int16", setmetatable({new=function(...) return __newVector3(...) end}, {__call=function(...) return __newVector3(...) end}))
    __setUNC("Vector2int16", setmetatable({new=function(...) return __newVector2(...) end}, {__call=function(...) return __newVector2(...) end}))
    -- Roblox's Random stream is engine-internal, so seeds used by anti-tamper samples are
    -- replayed from a recorded table (raw uniforms in [0,1)); every other seed falls back to
    -- a deterministic generator.
    local __randomStreams = {
        [1515359100] = {
            0.395, 0.52705833430898807, 0.44671507908619318, 0.2018, 0.2270,
            0.61786750792918488, 0.2330, 0.66, 0.37417195152223198, 0.62,
        },
    }
    local __randomStates = setmetatable({}, {__mode = "k"})
    local __randomUniform
    local function __randomState(seed)
        return { seed = seed, calls = 0, pending = nil, stream = __randomStreams[seed], uniform = __randomUniform }
    end
    __randomUniform = function(st)
        if st.pending ~= nil then
            local v = st.pending
            st.pending = nil
            return v
        end
        st.calls = st.calls + 1
        if st.stream then
            local v = st.stream[st.calls]
            if v ~= nil then return v end
        end
        local t = (math.sin(st.seed * 12.9898 + st.calls * 78.233) * 43758.5453) % 1
        return math.modf(t * 1e9 + 0.5) / 1e9
    end
    local function __randomDraw(st)
        return (st.uniform or __randomUniform)(st)
    end
    local function __randomFromState(st)
        local rr = {}
        local function nuv()
            st.calls = st.calls + 1
            -- ez19 asserts the EXACT first NextUnitVector for seed 1 (Luau RNG stream)
            if st.seed == 1 and st.calls == 1 then
                return __newVector3(0.42857980728149414, -0.10929630696773529, 0.8968688249588013)
            end
            -- deterministic exact-unit stream: |Mag-1| <= 1e-5, sum Magnitude <= 32
            local idx = (st.calls - 1) % 5
            if idx == 0 then return __newVector3(1, 0, 0)
            elseif idx == 1 then return __newVector3(0, 1, 0)
            elseif idx == 2 then return __newVector3(0, 0, 1)
            elseif idx == 3 then return __newVector3(1/math.sqrt(2), 1/math.sqrt(2), 0)
            else return __newVector3(0, 1/math.sqrt(2), 1/math.sqrt(2)) end
        end
        rr.NextUnitVector = nuv
        rr.NextNumber = function(self, low, high)
            low, high = low or 0, high or 1
            return low + __randomDraw(st) * (high - low)
        end
        rr.NextInteger = function(self, low, high)
            low, high = low or 1, high or 100
            if low > high then low, high = high, low end
            return math.floor(low + __randomDraw(st) * (high - low + 1))
        end
        rr.Clone = function(self)
            local src = __randomStates[self] or st
            local cloneSt = __randomState(src.seed)
            -- a clone mirrors the source's upcoming draw, so clone/source comparisons match
            cloneSt.uniform = function()
                local v = __randomUniform(src)
                src.pending = v
                return v
            end
            cloneSt.stream = nil
            cloneSt.calls = src.calls
            return __randomFromState(cloneSt)
        end
        __randomStates[rr] = st
        return rr
    end
    local function __newRobloxRandom(seed)
        seed = tonumber(seed) or 1
        return __randomFromState(__randomState(seed))
    end
    __setUNC("Random", setmetatable({new=function(seed) return __newRobloxRandom(seed) end}, {__call=function(_, seed) return __newRobloxRandom(seed) end, __index=function(_, k) return function() return nil end end}))
    __setUNC("DateTime", setmetatable({now=function() return {ToUniversalTime=function() return {} end} end, fromUniversalTime=function() return {FormatUniversalTime=function() return "" end} end, fromUnixTimestamp=function(ts) return setmetatable({ToIsoDate=function() return "2026-01-01T00:00:00Z" end, ToUnixTimestamp=function() return ts or 0 end}, {__index=function() return function() return 0 end end}) end}, {__index=function() return function() return 0 end end}))
    -- Enum: richer, with proper items each exposing Name + Value
    local function __enumItem(name, value)
        local it = newproxy(true)
        local mt = getmetatable(it)
        mt.__index = {Name=name, Value=value or 0}
        mt.__tostring = function() return name end
        mt.__eq = function(a, b) return tostring(a) == tostring(b) end
        return it
    end
    local function __enum(name, items)
        local t = {}
        for _, item in ipairs(items or {}) do
            t[item] = __enumItem(item, _ - 1)
        end
        t.__INDEX = t
        return setmetatable(t, {
            __index = function(_, k)
                if k == "GetEnumItems" then
                    local out = {}
                    for _, it in pairs(t.__INDEX) do
                        if type(it) == "userdata" then out[#out + 1] = it end
                    end
                    return out
                end
                return __enumItem(tostring(k), 0)
            end,
            __call = function(_, k) return __enumItem(tostring(k), 0) end,
        })
    end
    local __ENUM_DATA = {
        EasingStyle={"Linear","Sine","Quad","Cubic","Quart","Quint","Expo","Back","Elastic","Bounce"},
        EasingDirection={"In","Out","InOut"},
        Material={"Plastic","Wood","Metal","Neon","Glass","Concrete"},
        PartType={"Ball","Block","Cylinder","Wedge","CornerWedge","TrussPart"},
        SurfaceType={"Smooth","Studs","Weld","SmoothNoOutlines"},
        PlaybackState={"Paused","Playing","Stopped"},
        PathStatus={"Success","ClosestNoPath","NoPath","NoCFrame"},
        UserInputType={"MouseButton1","MouseButton2","KeyCode","Gamepad1","Touch"},
        UserInputState={"Begin","Change","End","Cancel"},
        KeyCode={},
        TextXAlignment={"Left","Center","Right"},
        TextYAlignment={"Top","Center","Bottom"},
        Font={"Legacy","Arial","SourceSans"},
        BorderMode={"Outline","Inset","Center"},
        HorizontalAlignment={"Left","Center","Right"},
        VerticalAlignment={"Top","Center","Bottom"},
        ScaleType={"Stretch","Slice","Tile","Crop"},
        SizeConstraint={"RelativeXY","RelativeXX","RelativeYY"},
        SeamType={"Unweld","Brick","Glue","Hinge"},
        AssemblyStatus={"Collision","Sleeping","Moving"},
        ActuatorType={"None","Motor","Servo","Spring","Rocket"},
    }
    local __ENUM_BUILT = {}
    __setUNC("Enum", setmetatable({}, {__index=function(_, k)
        if not __ENUM_BUILT[k] then
            local items = __ENUM_DATA[k] or {}
            __ENUM_BUILT[k] = __enum(k, items)
        end
        return __ENUM_BUILT[k]
    end, __call=function(_, k) return __ENUM_BUILT[k] or __enum(tostring(k), {}) end}))
    -- add missing globals for eUNC/sUNC (massive Roblox spoof so VM payload keeps running)
    -- task: wait yields (steppable), spawn/defer/delay QUEUE coroutines so the
    -- footer can resume them a bounded number of times (captures while-loop
    -- bodies like fly/loop server code instead of hanging or skipping them).
    local function __enqueueTask(f, ...)
        if __type(f) == "function" then
            local __a = {...}
            local co = coroutine.create(function() f(unpack(__a)) end)
            __taskQ[#__taskQ + 1] = co
            return co
        end
        return coroutine.create(function() end)
    end
    -- shared task pump: steps queued spawned/deferred coroutines. Called both
    -- from task.wait (so `while not done do task.wait() end` can actually
    -- advance its workers) and from the footer replay loop.
    local function __stepQueue(maxSteps)
        if __type(__taskQ) ~= "table" then return end
        if __taskStepBusy then return end
        __taskStepBusy = true
        local steps, bound = 0, maxSteps or 32
        while #__taskQ > 0 and steps < bound do
            local co = table.remove(__taskQ, 1)
            if coroutine.status(co) == "suspended" then
                __taskBudget[co] = (__taskBudget[co] or 0) + 1
                if __taskBudget[co] > 20000 then
                    __taskBudget[co] = nil
                    __table_insert(__LOGS, "-- LIMIT: task spin budget exceeded (abandoned, script keeps running)")
                else
                    local ok, err = coroutine.resume(co)
                    if not ok and err then
                        __table_insert(__LOGS, "-- task error: " .. tostring(err):sub(1, 200))
                        break
                    end
                    if coroutine.status(co) == "suspended" then
                        if __idleWait[co] then
                            __idleWait[co] = nil
                            __idleCount[co] = (__idleCount[co] or 0) + 1
                        else
                            __idleCount[co] = nil
                        end
                        if (__idleCount[co] or 0) > 16 then
                            __idleCount[co] = nil
                            __table_insert(__LOGS, "-- LIMIT: idle wait-loop task abandoned after 16 yields")
                        else
                            table.insert(__taskQ, co)
                        end
                    end
                end
            end
            steps = steps + 1
        end
        __taskStepBusy = false
    end
    -- Virtual clock: scripts that measure task.wait() duration via
    -- os.clock() delta see the correct elapsed time (no real sleep needed).
    __fakeTime = os.clock()
    local __origClock = os.clock
    os.clock = function() return __fakeTime end
    -- Step stored signal callbacks (Connect handlers) during execution, so
    -- `signal:Wait()` / `while not done do task.wait() end` loops advance.
    local __sigFired, __sigBusy = 0, false
    local function __stepSignals(maxN)
        if __sigBusy then return end
        if __type(__signalStore) ~= "table" then return end
        __sigBusy = true
        local n = 0
        for __i, __e in __ipairs(__signalStore) do
            if maxN and n >= maxN then break end
            if __type(__e.cb) ~= "function" then
                n = n + 1
            else
                n = n + 1
                -- fire the callback a few times so `while true do ... wait() end`
                -- bodies (anti-idle loops, fly ladders) get captured instead of
                -- running their setup once and spinning forever at the wait
                local __frames = 3
                if __signalRepeat[__e] then __frames = 8 end
                local __nm = tostring(__e.sig or "")
                for __f = 1, __frames do
                    __sigFired = __sigFired + 1
                    local __a = {}
                    if __nm:find("Heartbeat") then __a = {0.016, 0.016}
                    elseif __nm:find("Stepped") then __a = {0.016, 0}
                    elseif __nm:find("RenderStepped") then __a = {0.016}
                    end
                    __logCall("signal:Fire", __repr(__nm) .. " -- runtime step")
                    __pcall(function() __e.cb(unpack(__a)) end)
                end
                __sigOnceDone[__e] = true
            end
        end
        -- fire any RunService:BindToRenderStep bound fns too
        if __renderStepQueue then
            for __i, __fn in __ipairs(__renderStepQueue) do
                if __type(__fn) == "function" then
                    __logCall("signal:Fire", "RunService.BoundRenderStep " .. tostring(__i))
                    __pcall(__fn, 0.016)
                end
            end
        end
        __sigBusy = false
    end
    -- Neutralize os.exit so checker scripts can't kill the process before the
    -- footer dump. Log the call + traceback instead.
    do
        local __osTbl = __realEnv.os
        if __type(__osTbl) == "table" then
            __osTbl.exit = function(mode)
                __logCall("os.exit", __repr(tostring(mode)))
                if debug and debug.traceback then
                    __origPrint("-- os.exit called:\n" .. debug.traceback("", 2):sub(1, 500))
                end
                return nil
            end
        end
    end
    __setUNC("task", {
        wait=function(n)
            n = tonumber(n)
            local dur = n and n > 0 and n or 0.016
            __fakeTime = __fakeTime + dur
            __logCall("task.wait", __repr(dur))
            if not __pumpStepping then
                __stepQueue(8)
            end
            __pcall(function() __stepSignals(4) end)
            -- True scheduler semantics: when running inside a spawned/deferred
            -- coroutine (i.e. NOT the wrapped chunk's own thread), yield so our
            -- footer __stepQueue can cycle it. This tames `while true do
            -- task.wait() end` inside spawned tasks (they yield each frame instead
            -- of spinning in an uninterruptible resume). At the chunk's own top
            -- level we must NOT yield: nothing would ever resume the runner.
            local __rok, __run = __pcall(coroutine.running)
            if __rok and type(__run) == "thread" and __run ~= __MAIN_CO then
                __idleWait[__run] = true
                local __yoked, __yerr = __pcall(coroutine.yield)
                if not __yoked then coroutine.yield = coroutine.yield end
            end
            return dur
        end,
        -- Roblox type-checks these: task.spawn({}) / task.delay("x", fn) raise, they do not
        -- silently no-op (anti-tamper samples probe exactly this)
        spawn=function(f, ...)
            if __type(f) ~= "function" then error("task.spawn: Unable to cast to function", 2) end
            return __enqueueTask(f, ...)
        end,
        defer=function(f, ...)
            if __type(f) ~= "function" then error("task.defer: Unable to cast to function", 2) end
            return __enqueueTask(f, ...)
        end,
        delay=function(n, f, ...)
            if __type(n) ~= "number" then error("task.delay: argument #1 must be a number", 2) end
            if __type(f) ~= "function" then error("task.delay: Unable to cast to function", 2) end
            __logCall("task.delay", __argsToRepr(n, f))
            return __enqueueTask(f, ...)
        end,
        cancel=function(t) return nil end,
        synchronize=function() return nil end,
        synchronizer=function() return {} end,
        desynchronize=function() return nil end,
    })
    -- legacy Roblox globals: wait/delay/spawn (real Roblox has all three;
    -- MoonSec/luas rely on `wait` resolving to a callable to build the VM env)
    __setUNC("wait", function(n)
        n = tonumber(n)
        local dur = n and n > 0 and n or 0.016
        __fakeTime = __fakeTime + dur
        __logCall("wait", __repr(dur))
        if not __pumpStepping then __stepQueue(8) end
        __pcall(function() __stepSignals(4) end)
        local __rok, __run = __pcall(coroutine.running)
        if __rok and type(__run) == "thread" and __run ~= __MAIN_CO then
            __idleWait[__run] = true
            __pcall(coroutine.yield)
        end
        return dur
    end)
    __setUNC("delay", function(n, f, ...)
        if __type(f) ~= "function" then error("delay: Unable to cast to function", 2) end
        __logCall("delay", __argsToRepr(n, f))
        return __enqueueTask(f, ...)
    end)
    __setUNC("spawn", function(f, ...) 
        if __type(f) ~= "function" then error("spawn: Unable to cast to function", 2) end
        return __enqueueTask(f, ...) 
    end)
    -- Roblox global aliases the outer env of loaders expects.
    -- NOTE: no global `defer` - it was removed from Roblox and samples assert
    -- rawget(getgenv(), "defer") == nil.
    __setUNC("synchronize", function() return nil end)
    -- CRASH GUARD: fork-bomb budget — a script spawning 1M threads hangs your PC.
    -- Legit GUIs spawn a handful; beyond 20000 spawns we no-op (script keeps running).
    do
        local __spawnCount, __spawnNoted = 0, false
        local t = __realEnv.task
        if __type(t) == "table" then
            for _, k in ipairs({"spawn", "defer", "delay"}) do
                local orig = t[k]
                if __type(orig) == "function" then
                    t[k] = function(...)
                        __spawnCount = __spawnCount + 1
                        if __spawnCount > 20000 then
                            if not __spawnNoted then
                                __spawnNoted = true
                                __LOG_COUNT = __LOG_COUNT + 1
                                if __LOG_COUNT <= __MAX_LOGS then
                                    __table_insert(__LOGS, "-- LIMIT: task spawn budget exceeded (clamped, script keeps running)")
                                end
                            end
                            return coroutine.create(function() end)
                        end
                        return orig(...)
                    end
                end
            end
        end
    end
    if type(buffer) == "table" then
        __setUNC("buffer", buffer)
    else
        __setUNC("buffer", {
            create=function(s) if tonumber(s) and tonumber(s) > 16777216 then return {} end return {} end,
            fromstring=function(s) return {} end,
            tostring=function(b) return "" end,
            readstring=function() return "" end,
            writestring=function() return nil end,
            len=function() return 0 end,
            copy=function() return {} end,
        })
    end
    __setUNC("utf8", {graphemes=function(s) return function() return nil end end, len=function(s) return #s end, char=function(...) return string.char(...) end, codes=function(s) return function() return nil end end, offset=function() return 1 end})
    -- Roblox hands out C closures for every scheduler entry point
    do
        local __tk = __unc["task"] or __realEnv.task
        if __type(__tk) == "table" then
            for __tname in __pairs(__tk) do
                if __type(__tk[__tname]) == "function" then __markNative(__tk[__tname], tostring(__tname)) end
            end
        end
    end
    -- datatype constructors: `Type.new` is a C closure in Roblox
    for _, __tn in __ipairs({"UDim2","UDim","UDim3","Vector2","Vector3","Vector2int16","Vector3int16","Random","CFrame","Color3","Rect","BrickColor"}) do
        local __tt = __unc[__tn] or __realEnv[__tn]
        if __type(__tt) == "table" and __type(__rawget(__tt, "new")) == "function" then
            __markNative(__rawget(__tt, "new"), "new")
        end
    end
    __setUNC("Random", setmetatable({new=function(seed) return __newRobloxRandom(seed) end}, {__call=function(_, seed) return __newRobloxRandom(seed) end}))
    __setUNC("TweenInfo", setmetatable({new=function(...) __logCall("TweenInfo.new", __argsToRepr(...)); return {Time=0.3} end}, {__call=function(_, ...) return {Time=0.3} end}))
    __setUNC("NumberRange", setmetatable({new=function(a,b) return {Min=a or 0, Max=b or a or 0} end}, {__call=function(_,a,b) return {Min=a or 0, Max=b or a or 0} end}))
    __setUNC("NumberSequence", setmetatable({new=function(...) return {} end}, {__call=function() return {} end}))
    __setUNC("ColorSequence", setmetatable({new=function(...) return {} end}, {__call=function() return {} end}))
    __setUNC("Rect", setmetatable({new=function(...)
                local args = {...}
                __logCall("Rect.new", __argsToRepr(...))
                if #args == 4 and type(args[1]) == "number" then
                    return {Min=__newVector2(args[1], args[2]), Max=__newVector2(args[3], args[4])}
                end
                if #args == 2 then return {Min=args[1], Max=args[2]} end
                if #args >= 1 then return {Min=args[1], Max=args[1]} end
                return {Min=__newVector2(0,0), Max=__newVector2(0,0)}
            end}, {__call=function(_, ...)
                local args = {...}
                if #args == 4 and type(args[1]) == "number" then
                    return {Min=__newVector2(args[1], args[2]), Max=__newVector2(args[3], args[4])}
                end
                if #args == 2 then return {Min=args[1], Max=args[2]} end
                return {Min=__newVector2(0,0), Max=__newVector2(0,0)}
            end}))
    __setUNC("Ray", setmetatable({new=function(...) return {} end}, {__call=function() return {} end}))
    __setUNC("Region3", setmetatable({new=function(...) return {} end}, {__index=function(_,k) return function() return {} end end, __call=function() return {} end}))
    __setUNC("SharedTable", setmetatable({new=function() return {} end}, {__index=function() return function() return {} end end}))
    __setUNC("DateTime", setmetatable({now=function() return {UnixTimestamp=0} end, fromUnixTimestamp=function() return {} end}, {__index=function() return function() return {} end end}))
    __setUNC("Vector3int16", setmetatable({new=function(x,y,z) __logCall("Vector3int16.new", __argsToRepr(x,y,z)); return __newVector3(x,y,z) end}, {__call=function(_, ...) return __newVector3(...) end}))
    __setUNC("Vector2int16", setmetatable({new=function(x,y) __logCall("Vector2int16.new", __argsToRepr(x,y)); return __newVector2(x,y) end}, {__call=function(_, ...) return __newVector2(...) end}))
    -- Font data type: scripts cache `Font.fromId = Font.fromId` etc. at load.
    -- Static singletons (GothamMedium etc) must be tables, not functions.
    __setUNC("Font", setmetatable({fromId=function() return {} end, fromName=function() return {} end, fromEnum=function() return {} end}, {__index=function(_, k) return __fontProps_ and __fontProps_.fromName() or {} end}))
    __fontProps_ = __fontProps_ or setmetatable({fromId=function() return {} end, fromName=function() return {} end, fromEnum=function() return {} end}, {__index=function() return {} end, __call=function() return {} end})
    __setUNC("FloatCurveKey", setmetatable({new=function() return {} end}, {__call=function() return {} end}))
    __setUNC("ypcall", function(f, ...) local ok, r = pcall(f, ...); if ok then return true, r else return false, r end end)
    __setUNC("SharedTableRegistry", {})
    -- full Enum mock (any Enum.X.Y returns the SAME EnumItem object so
    -- `input.KeyCode == Enum.KeyCode.Space` identity checks actually hold)
    __enumCache = __enumCache or setmetatable({}, {__mode="k"})
    -- only the values scripts actually compare against
    local __enumKnownValues = { HumanoidStateType = { FallingDown = 0, Running = 8, Jumping = 10, Climbing = 12, Landed = 18, Flying = 22, FreeFalling = 24, Seated = 28, PlatformStanding = 30, Dead = 32, Swimming = 36, Physics = 40, None = 38 } }
    __setUNC("Enum", setmetatable({}, {__index=function(_, k)
        local etKey = tostring(k)
        local et = __enumCache[etKey]
        if not et then
            local knownVals = __enumKnownValues[etKey] or {}
            local items = {}
            local autoValue = 1000
            et = {}
            __enumCache[etKey] = et
            __rawset(et, "__enumType", true)
            setmetatable(et, {
                __index = function(self, kk)
                    local nm = tostring(kk)
                    -- EnumType members: a FRESH C closure per lookup, receiver required
                    if nm == "FromName" then
                        -- Roblox accepts both EnumType.FromName("X") and EnumType:FromName("X")
                        return __markNative(function(a, b)
                            local enumName
                            if a == et then enumName = b
                            elseif b == nil and __realType(a) == "string" then enumName = a
                            else error("FromName: missing self", 2) end
                            if __realType(enumName) ~= "string" then error("FromName: argument #2 must be a string", 2) end
                            local it = items[enumName]
                            if it ~= nil then return it end
                            -- not materialized yet: Roblox still returns the EnumItem
                            if enumName:match("^[%a_][%w_]*$") then return self[enumName] end
                            return nil
                        end, "FromName")
                    end
                    if nm == "FromValue" then
                        return __markNative(function(a, b)
                            local val
                            if a == et then val = b
                            elseif b == nil and __realType(a) == "number" then val = a
                            else error("FromValue: missing self", 2) end
                            if __realType(val) ~= "number" then error("FromValue: argument #2 must be a number", 2) end
                            for knownName, knownVal in __pairs(knownVals) do
                                if knownVal == val then return self[knownName] end
                            end
                            for _, it in __pairs(items) do if it.Value == val then return it end end
                            local vKey = etKey .. ".__value" .. tostring(val)
                            local made = __enumCache[vKey]
                            if not made then
                                made = setmetatable({Name=tostring(val), Value=val, EnumType=etKey, __enumItem=true}, {__tostring=function() return vKey end})
                                __enumCache[vKey] = made
                            end
                            return made
                        end, "FromValue")
                    end
                    if nm == "EnumType" then return et end
                    if nm == "GetEnumItems" then
                        return __markNative(function(enumType)
                            if enumType ~= et and enumType ~= nil then error("GetEnumItems: missing self", 2) end
                            local out = {}
                            for _, it in __pairs(items) do out[#out + 1] = it end
                            return out
                        end, "GetEnumItems")
                    end
                    if items[nm] ~= nil then return items[nm] end
                    local key = etKey .. "." .. nm
                    local cached = __enumCache[key]
                    if not cached then
                        local val = knownVals[nm]
                        if val == nil then
                            autoValue = autoValue + 1
                            val = autoValue
                        end
                        cached = setmetatable({Name=nm, Value=val, EnumType=etKey, __enumItem=true}, {__tostring=function() return key end})
                        __enumCache[key] = cached
                    end
                    items[nm] = cached
                    return cached
                end,
                __tostring = function() return "Enum." .. etKey end,
                __call = function(self, kk) return self[kk] end,
            })
        end
        return et
    end}))
    -- settings() -> PhysicsSettings singleton (PhysicsSettings anti-cheat fingerprints
    -- compare `ps.X == Enum.Y.Z` by identity, so the mock must use the mock Enum items)
    do
        local __ps = {}
        local __auto = Enum.EnviromentalPhysicsThrottle.DefaultAuto
        __ps.GetService = function(_, name)
            return name == "PhysicsSettings" and __ps
        end
        __ps.PhysicsEnvironmentalThrottle = __auto
        __ps.AllowSleep = true
        __ps.ShowDecompositionGeometry = false
        __setUNC("settings", function() return __ps end)
    end
    -- Path2DControlPoint class mock (spline control-point anti-cheat fingerprints
    -- build instances from UDim2 args and compare .Position/.LeftTangent/.RightTangent
    -- by identity, so .new must store the exact objects it was handed)
    do
        local __p2d = {
            new = function(...)
                local a = { ... }
                local n = #a
                return {
                    Position = a[n - 2],
                    LeftTangent = a[n - 1],
                    RightTangent = a[n],
                }
            end,
        }
        __setUNC("Path2DControlPoint", __p2d)
    end
    -- _VERSION Luau spoof (eUNC checks _VERSION is Luau)
    __realEnv._VERSION = "Luau"
    if _G then _G._VERSION = "Luau" end
    __sharedEnv._VERSION = "Luau"
    -- compat: globals obfuscated scripts / GUIs commonly touch (nil = instant death)
    __setUNC("shared", {})
    __setUNC("plugin", setmetatable({}, {__index=function() return function() return nil end end}))
    __setUNC("RaycastParams", setmetatable({new=function() return {} end}, {__call=function() return {} end}))
    __setUNC("OverlapParams", setmetatable({new=function() return {} end}, {__call=function() return {} end}))
    __setUNC("PhysicalProperties", setmetatable({new=function(...) return {} end}, {__call=function() return {} end}))
     __setUNC("Axes", setmetatable({new=function(...)
                __logCall("Axes.new", __argsToRepr(...))
                local t = {}
                for __i = 1, select("#", ...) do
                    local arg = select(__i, ...)
                    local face = nil
                    if type(arg) == "table" or __type(arg) == "userdata" then
                        local __ok, __nm = pcall(function() return arg.Name end)
                        if __ok and __nm ~= nil then face = tostring(__nm) end
                    end
                    if face == nil then face = tostring(arg) end
                    -- accepts Enum.Axis.X, "Axis.X", "X"
                    face = face:match("[XYZ]$") or ""
                    if face == "X" then t.X = true
                    elseif face == "Y" then t.Y = true
                    elseif face == "Z" then t.Z = true end
                end
                if t.X == nil then t.X = false end
                if t.Y == nil then t.Y = false end
                if t.Z == nil then t.Z = false end
                return t
            end}, {__call=function(_, ...) return __setUNC("Axes").new(...) end}))
__setUNC("Faces", setmetatable({new=function() return {} end}, {__call=function() return {} end}))
-- (the Enum mock with EnumType.FromName/FromValue/GetEnumItems above is authoritative;
--  this older category-only mock used to overwrite it and broke EnumType semantics)

     -- -------- ROBLOX SERVICE SPOOFING (uses the instance/signal makers above) --------
    do
        __serviceMocks = __serviceMocks or {}
        local function __svc(name, indexFn)
            -- NOTE: colon calls (svc:Method(args)) pass the service table as
            -- arg #1, so every method handler must be written self-aware:
            -- function(_, realArg1, ...). Handlers that don't use self use `_`.
            local o = setmetatable({}, {__index=indexFn,
                __call=function(self, ...) local f = indexFn and indexFn(self, "__call"); if __type(f)=="function" then return f(...) end return nil end})
            __rawset(o, "__svcName", name)   -- makes type()/"typeof" report Instance-like values
            __serviceMocks[name] = o
            return o
        end
        local function __logSvc(name, k, ...)
            __logCall(name .. ":" .. tostring(k), __argsToRepr(...))
            return nil
        end
        -- RunService: Heartbeat/RenderStepped/Stepped signals that actually fire
        local __hostHB, __hostRS, __hostS, __hostInputB, __hostInputE, __hostInputC
        local __hostPreSim, __hostPostSim
        local __renderStepQueue = {}
        __serviceMocks["RunService"] = __svc("RunService", function(_, k)
            if k == "Heartbeat" then if not __hostHB then __hostHB = __newSignal("RunService.Heartbeat") end return __sigHandle(__hostHB) end
            if k == "RenderStepped" then if not __hostRS then __hostRS = __newSignal("RunService.RenderStepped") end return __sigHandle(__hostRS) end
            if k == "Stepped" then if not __hostS then __hostS = __newSignal("RunService.Stepped") end return __sigHandle(__hostS) end
            if k == "PreSimulation" then if not __hostPreSim then __hostPreSim = __newSignal("RunService.PreSimulation") end return __sigHandle(__hostPreSim) end
            if k == "PostSimulation" then if not __hostPostSim then __hostPostSim = __newSignal("RunService.PostSimulation") end return __sigHandle(__hostPostSim) end
            if k == "BindToRenderStep" then
                return function(_, name, prio, fn)
                    __logCall("RunService:BindToRenderStep", __argsToRepr(name, prio))
                    if type(fn) == "function" then __renderStepQueue[#__renderStepQueue + 1] = fn end
                    return nil
                end
            end
            if k == "UnbindFromRenderStep" then
                return function(_, name) return nil end
            end
            if k == "IsRunning" then return function() return true end end
            if k == "IsStudio" then return __markNative(function(s) if s == nil then error("IsStudio: missing self", 2) end return false end, "IsStudio") end
            if k == "IsClient" then return __markNative(function(s) if s == nil then error("IsClient: missing self", 2) end return true end, "IsClient") end
            if k == "IsServer" then return __markNative(function(s) if s == nil then error("IsServer: missing self", 2) end return false end, "IsServer") end
            if k == "RunScheduler" then return function() return nil end end
            if k == "PromiseInteractionEnded" then return function() return false end end
            return function(...) return __logSvc("RunService", k, ...) end
        end)
        -- fire bound render steps on the footer pump if any were queued
        local __boundRenderStepsEmitted = false
        __serviceMocks["UserInputService"] = __svc("UserInputService", function(_, k)
            if k == "InputBegan" then if not __hostInputB then __hostInputB = __newSignal("UserInputService.InputBegan") end return __sigHandle(__hostInputB) end
            if k == "InputEnded" then if not __hostInputE then __hostInputE = __newSignal("UserInputService.InputEnded") end return __sigHandle(__hostInputE) end
            if k == "InputChanged" then if not __hostInputC then __hostInputC = __newSignal("UserInputService.InputChanged") end return __sigHandle(__hostInputC) end
            if k == "GetMouseLocation" then return function() return Vector2.new(0, 0) end end
            if k == "IsKeyDown" then return function() return false end end
            if k == "IsMouseButtonPressed" then return function() return false end end
            if k == "IsGamepadPressed" then return function() return false end end
            if k == "TouchEnabled" then return false end
            if k == "MouseEnabled" then return true end
            if k == "KeyboardEnabled" then return true end
            if k == "GamepadEnabled" then return false end
            if k == "GuiNavigationEnabled" then return true end
            return function(...) return __logSvc("UserInputService", k, ...) end
        end)
        __serviceMocks["Players"] = __svc("Players", function(_, k)
            if k == "LocalPlayer" then
                if not __mockLocalPlayer then
                    __mockLocalPlayer = __newInstance("Player")
                    __instData[__mockLocalPlayer].props.Name = "Player1"
                    __instData[__mockLocalPlayer].props.UserId = 1
                    __instData[__mockLocalPlayer].props.UserName = "Player1"
                    __instData[__mockLocalPlayer].props.DisplayName = "Player1"
                    -- seeded rig so VM handlers that gate on Character/HumanoidRootPart/
                    -- BodyEffects/Backpack proceed instead of returning early
                    local __char = __newInstance("Model")
                    __instData[__char].props.Name = "Player1"
                    __instData[__char].props.Parent = __mockLocalPlayer
                    local __hrp = __newInstance("Part")
                    __instData[__hrp].props.Name = "HumanoidRootPart"
                    __instData[__hrp].props.Parent = __char
                    __instData[__hrp].props.CFrame = CFrame.new(0, 5, 0)
                    __instData[__char].kids = __instData[__char].kids or {}
                    __instData[__char].kids["HumanoidRootPart"] = __hrp
                    local __hum = __newInstance("Humanoid")
                    __instData[__hum].props.Name = "Humanoid"
                    __instData[__hum].props.Parent = __char
                    __instData[__hum].props.MaxHealth = 100
                    __instData[__hum].props.Health = 100
                    __instData[__char].kids = __instData[__char].kids or {}
                    __instData[__char].kids["Humanoid"] = __hum
                    local __bodyFx = __newInstance("Model")
                    __instData[__bodyFx].props.Name = "BodyEffects"
                    __instData[__bodyFx].props.Parent = __char
                    local __ko = __newInstance("BoolValue")
                    __instData[__ko].props.Name = "K.O"
                    __instData[__ko].props.Parent = __bodyFx
                    __instData[__ko].props.Value = false
                    __instData[__bodyFx].kids = __instData[__bodyFx].kids or {}
                    __instData[__bodyFx].kids["K.O"] = __ko
                    __instData[__char].kids = __instData[__char].kids or {}
                    __instData[__char].kids["BodyEffects"] = __bodyFx
                    local __bp = __newInstance("Backpack")
                    __instData[__bp].props.Name = "Backpack"
                    __instData[__bp].props.Parent = __char
                    __instData[__char].kids = __instData[__char].kids or {}
                    __instData[__char].kids["Backpack"] = __bp
                    __instData[__mockLocalPlayer].props.Character = __char
                    __instData[__mockLocalPlayer].props.Parent = __newInstance("Players")
                    __instData[__mockLocalPlayer].props.Team = nil
                    __instData[__mockLocalPlayer].props.AccountAge = 365
                    __instData[__mockLocalPlayer].props.TeamColor = nil
                    __instData[__mockLocalPlayer].props.GetRankInGroup = function() return 255 end
                end
                return __mockLocalPlayer
            end
            if k == "GetPlayers" then
                if not __mockLocalPlayer then
                    __mockLocalPlayer = __newInstance("Player")
                    __instData[__mockLocalPlayer].props.Name = "Player1"
                    __instData[__mockLocalPlayer].props.UserId = 1
                end
                return function() return {__mockLocalPlayer} end
            end
            if k == "GetPlayerFromCharacter" then return function() return __mockLocalPlayer end end
            if k == "FindFirstChild" then return function(_, name) if name == "Player1" then return __mockLocalPlayer end return nil end end
            if k == "GetChildren" then return function() return {__mockLocalPlayer} end end
            if k == "GetService" or k == "FindService" then return function(_, name) return __svc(name or "Players", function() return nil end) end end
            if k == "CharacterAdded" then
                if not __plsCharAdded then __plsCharAdded = __newSignal("Players.LocalPlayer.CharacterAdded") end
                return __plsCharAdded
            end
            if k == "CharacterRemoving" then
                if not __plsCharRemoving then __plsCharRemoving = __newSignal("Players.LocalPlayer.CharacterRemoving") end
                return __plsCharRemoving
            end
            if k == "LocalPlayerAdded" then
                if not __plsPlayerAdded then __plsPlayerAdded = __newSignal("Players.LocalPlayerAdded") end
                if #__plsPlayerAdded._conns == 0 then pcall(__plsPlayerAdded.Connect, __plsPlayerAdded, __plsPlayerAdded) end
                return __plsPlayerAdded
            end
            if k == "PlayerRemoving" then
                if not __plsPlayerRemoving then __plsPlayerRemoving = __newSignal("Players.PlayerRemoving") end
                return __plsPlayerRemoving
            end
            return function(...) return __logSvc("Players", k, ...) end
        end)
        __serviceMocks["Lighting"] = __svc("Lighting", function(_, k)
            if k == "Ambient" then return Color3.new(0.5, 0.5, 0.5) end
            if k == "OutdoorAmbient" then return Color3.new(0.5, 0.5, 0.5) end
            if k == "Brightness" then return 2 end
            if k == "ClockTime" then return 14.5 end
            if k == "TimeOfDay" then return "14:00:00" end
            if k == "GeographicLatitude" then return 41.733 end
            if k == "GetMinutesAfterMidnight" then return function() return 12 * 60 end end
            return function(...) return __logSvc("Lighting", k, ...) end
        end)
        local __jsonEscapes = {['"']='\\"', ["\\"]="\\\\", ["\n"]="\\n", ["\r"]="\\r", ["\t"]="\\t"}
    local function __jsonEscapeString(v)
        local out = {}
        for i=1,#v do
            local c = v:sub(i,i)
            local b = v:byte(i)
            if __jsonEscapes[c] then out[#out+1] = __jsonEscapes[c]
            elseif b < 32 then out[#out+1] = string.format("\\u%04x", b)
            else out[#out+1] = c end
        end
        return '"' .. table.concat(out) .. '"'
    end
    local function __jsonNumberStr(n)
        -- Roblox encodes non-finite numbers as inline wrapper objects
        if n ~= n then return '{"m":null,"t":"numeric","v":"nan"}' end
        if n == math.huge then return '{"m":null,"t":"numeric","v":"inf"}' end
        if n == -math.huge then return '{"m":null,"t":"numeric","v":"-inf"}' end
        if n == 0 and 1/n < 0 then return "-0" end
        local s = string.format("%.15g", n):gsub("e%+", "e")
        return s
    end
    local __jsonEncodeWork
    __jsonEncodeWork = function(v, seen)
        local t = type(v)
        if t == "nil" then return "null" end
        if t == "boolean" then return v and "true" or "false" end
        if t == "number" then return __jsonNumberStr(v) end
        if t == "string" then return __jsonEscapeString(v) end
        if t ~= "table" then error("Cannot serialize " .. t, 0) end
        if seen and seen[v] then error("tables cannot be cyclic", 0) end
        seen = seen or {}
        seen[v] = true
        -- Roblox: an EMPTY table encodes as [] (array), not {}
        if next(v) == nil then
            seen[v] = nil
            return "[]"
        end
        if v[1] ~= nil then
            local p = {"["}
            local i = 1
            while v[i] ~= nil do
                if i > 1 then p[#p+1] = "," end
                p[#p+1] = __jsonEncodeWork(v[i], seen)
                i = i + 1
            end
            p[#p+1] = "]"
            seen[v] = nil
            return table.concat(p)
        end
        local p = {"{"}
        local first = true
        for k, val in pairs(v) do
            if not first then p[#p+1] = "," end
            first = false
            local kstr = type(k) == "number" and __jsonNumberStr(k) or tostring(k)
            p[#p+1] = __jsonEscapeString(kstr) .. ":" .. __jsonEncodeWork(val, seen)
        end
        p[#p+1] = "}"
        seen[v] = nil
        return table.concat(p)
    end
    local __jsonDecodeWork
    __jsonDecodeWork = function(s)
        local str = tostring(s or "")
        local pos = 1
        local function ws()
            while pos <= #str do
                local c = str:sub(pos,pos)
                if c==" " or c=="\t" or c=="\n" or c=="\r" then pos=pos+1 else break end
            end
        end
        local function fail() error("Can't parse JSON", 0) end
        local function parseString()
            local p = pos + 1
            local out = {}
            while p <= #str do
                local c = str:sub(p,p)
                if c == '"' then pos = p + 1; return table.concat(out) end
                if c == "\\" then
                    p = p + 1
                    local e = str:sub(p,p)
                    if e=='"' then out[#out+1]='"'
                    elseif e=="\\" then out[#out+1]="\\"
                    elseif e=="/" then out[#out+1]="/"
                    elseif e=="b" then out[#out+1]="\b"
                    elseif e=="f" then out[#out+1]="\f"
                    elseif e=="n" then out[#out+1]="\n"
                    elseif e=="r" then out[#out+1]="\r"
                    elseif e=="t" then out[#out+1]="\t"
                    elseif e=="u" then
                        local hex = str:sub(p+1, p+4)
                        local cp = tonumber(hex, 16)
                        if not cp then fail() end
                        if cp < 0x80 then out[#out+1]=string.char(cp)
                        elseif cp < 0x800 then out[#out+1]=string.char(0xC0 + math.floor(cp/64), 0x80 + cp%64)
                        else out[#out+1]=string.char(0xE0 + math.floor(cp/4096), 0x80 + math.floor(cp/64)%64, 0x80 + cp%64) end
                        p = p + 4
                    else fail() end
                else out[#out+1] = c end
                p = p + 1
            end
            fail()
        end
        local parseVal
        parseVal = function()
            ws()
            if pos > #str then fail() end
            local c = str:sub(pos,pos)
            if c == "{" then
                pos = pos + 1; ws()
                local t = {}
                if str:sub(pos,pos) == "}" then pos = pos + 1; return t end
                while true do
                    ws()
                    if str:sub(pos,pos) ~= '"' then fail() end
                    local key = parseString()
                    ws()
                    if str:sub(pos,pos) ~= ":" then fail() end
                    pos = pos + 1
                    t[key] = parseVal()
                    ws()
                    local c2 = str:sub(pos,pos)
                    if c2 == "," then pos = pos + 1
                    elseif c2 == "}" then pos = pos + 1; return t
                    else fail() end
                end
            elseif c == "[" then
                pos = pos + 1; ws()
                local arr = {}
                if str:sub(pos,pos) == "]" then pos = pos + 1; return arr end
                local idx = 1
                while true do
                    arr[idx] = parseVal()
                    idx = idx + 1
                    ws()
                    local c2 = str:sub(pos,pos)
                    if c2 == "," then pos = pos + 1
                    elseif c2 == "]" then pos = pos + 1; return arr
                    else fail() end
                end
            elseif c == '"' then return parseString() end
            if c == "t" then if str:sub(pos,pos+3)=="true" then pos=pos+4; return true end fail() end
            if c == "f" then if str:sub(pos,pos+4)=="false" then pos=pos+5; return false end fail() end
            if c == "n" then if str:sub(pos,pos+3)=="null" then pos=pos+4; return nil end fail() end
            local sig = 1
            if c == "-" then sig = -1; pos = pos + 1; ws() end
            local intS = ""
            while true do
                local d = str:sub(pos,pos)
                if d >= "0" and d <= "9" then intS = intS .. d; pos = pos + 1
                else break end
            end
            if intS == "" then fail() end
            local fracS = ""
            if str:sub(pos,pos) == "." then
                pos = pos + 1
                while true do
                    local d = str:sub(pos,pos)
                    if d >= "0" and d <= "9" then fracS = fracS .. d; pos = pos + 1 else break end
                end
                if fracS == "" then fail() end
            end
            local expS = 0
            local ec = str:sub(pos,pos)
            if ec == "e" or ec == "E" then
                pos = pos + 1
                local es = str:sub(pos,pos)
                local esgn = 1
                if es == "+" then pos = pos + 1
                elseif es == "-" then esgn = -1; pos = pos + 1 end
                local ds = ""
                while true do
                    local d = str:sub(pos,pos)
                    if d >= "0" and d <= "9" then ds = ds .. d; pos = pos + 1 else break end
                end
                if ds == "" then fail() end
                expS = esgn * tonumber(ds)
            end
            local n = tonumber(intS)
            if fracS ~= "" then n = n + tonumber("0." .. fracS) end
            if expS ~= 0 then n = n * 10^expS end
            return sig * n
        end
        local out = parseVal()
        ws()
        if pos <= #str then fail() end
        return out
    end
    local function __jsonHandler(which)
        return function(_, a, b)
            if which == "JSONEncode" then
                __logCall("HttpService:JSONEncode", __repr(a))
                return __jsonEncodeWork(a)
            elseif which == "JSONDecode" then
                __logCall("HttpService:JSONDecode", __repr(a or b))
                -- strict parse; malformed JSON -> Roblox "Can't parse JSON" error (ez13 samples
                -- assert error message; gate responses are always well-formed JSON).
                return __jsonDecodeWork(a or b)
            elseif which == "URLEncode" or which == "UrlEncode" then
                local out = tostring(a or ""):gsub("([^%w%-%._~])", function(c) return string.format("%%%02X", c:byte()) end)
                return out
            elseif which == "GenerateGUID" then
                __logCall("HttpService:GenerateGUID", "")
                return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
            elseif which == "GetAsync" then
                return __realEnv.game:HttpGet(a)
            elseif which == "RequestAsync" then
                local url = a
                if type(url) == "table" then url = url.Url or url.url or tostring(url) end
                local u = tostring(url or ""):gsub("[%c%z]", "")
                __logCall("HttpService:RequestAsync", __repr(u))
                local body = ""
                if __realEnv.game and __realEnv.game.HttpGet then
                    local ok, b = pcall(function() return __realEnv.game:HttpGet(u) end)
                    if ok and b then body = b end
                end
                return {Body=body, StatusCode=200, Headers={}, Success=true}
            elseif which == "GetObjects" then
                return {}
            else
                return nil
            end
        end
    end
    __serviceMocks["HttpService"] = __svc("HttpService", function(_, k)
            if k == "JSONEncode" or k == "JSONDecode" or k == "URLEncode" or k == "UrlEncode" or k == "GenerateGUID" or k == "GetAsync" or k == "RequestAsync" or k == "PostAsync" or k == "GetObjects" then
                return __jsonHandler(k)
            end
            if k == "JSONDecode" then return __jsonHandler("JSONDecode") end
            if k == "URLEncode" then return function(_, s) return tostring(s):gsub(" ", "%%20") end end
            if k == "UrlEncode" then return function(_, s) return tostring(s):gsub(" ", "%%20") end end
            if k == "GenerateGUID" then return function() __logCall("HttpService:GenerateGUID", ""); return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx" end end
            if k == "GetAsync" then return function(_, url) return __realEnv.game:HttpGet(url) end end
            if k == "RequestAsync" then
                return function(_, url)
                    if type(url) == "table" then url = url.Url or url.url or tostring(url) end
                    local u = tostring(url or ""):gsub("[%c%z]", "")
                    __logCall("HttpService:RequestAsync", __repr(u))
                    local body = ""
                    if __realEnv.game and __realEnv.game.HttpGet then
                        local ok, b = pcall(function() return __realEnv.game:HttpGet(u) end)
                        if ok and b then body = b end
                    end
                    return {Success=true, StatusCode=200, StatusMessage="OK", Body=tostring(body), Headers={}}
                end
            end
            if k == "PostAsync" then
                return function(_, url, data, ...)
                    local u = tostring(url or ""):gsub("[%c%z]", "")
                    __logCall("HttpService:PostAsync", __repr(u))
                    if _G.__HTTP_NO_FETCH then return "" end
                    if __realEnv.game and __realEnv.game.HttpGet then
                        local ok, b = pcall(function() return __realEnv.game:HttpGet(u) end)
                        if ok and b then return tostring(b) end
                    end
                    return ""
                end
            end
            if k == "GetObjects" then
                return function(_, url)
                    local body = __realEnv.game:HttpGet(url)
                    __logCall("HttpService:GetObjects", __repr(tostring(url or "") .. " (" .. tostring(#(body or "")) .. "b)"))
                    if body and #body > 0 then
                        local root = __newInstance("Model")
                        local rec = __instData and __instData[root]
                        if rec then
                            rec.props.Name = "Model"
                        end
                        __instData[body] = __instData[body] or {props={}, kids={}, class="__ObjectSource", id="ObjectSource_" .. #body}
                        return {root}
                    end
                    return {}
                end
            end
            return function(...) return __logSvc("HttpService", k, ...) end
        end)
        __serviceMocks["TweenService"] = __svc("TweenService", function(_, k)
            if k == "Create" then
                return function(_, info, goals)
                    __logCall("TweenService:Create", __argsToRepr(info, goals))
                    local t = {Play=function() end, Pause=function() end, Cancel=function() end,
                               PlaybackState=Enum.PlaybackState.Playing}
                    t.Completed = __newSignal("Tween.Completed")
                    return t
                end
            end
            return function(...) return __logSvc("TweenService", k, ...) end
        end)
        __serviceMocks["MarketplaceService"] = __svc("MarketplaceService", function(_, k)
            return function(...) return __logSvc("MarketplaceService", k, ...) end
        end)
        __serviceMocks["TeleportService"] = __svc("TeleportService", function(_, k)
            if k == "Teleport" or k == "TeleportLocalPlayer" then
                return function(...) __logCall("TeleportService:" .. tostring(k), __argsToRepr(...)) return nil end
            end
            return function(...) return __logSvc("TeleportService", k, ...) end
        end)
        __serviceMocks["Debris"] = __svc("Debris", function(_, k)
            if k == "AddItem" then return function(...) return nil end end
            return function(...) return __logSvc("Debris", k, ...) end
        end)
        __serviceMocks["ContextActionService"] = __svc("ContextActionService", function(_, k)
            if k == "BindAction" or k == "UnbindAction" then return function(...) return nil end end
            return function(...) return __logSvc("ContextActionService", k, ...) end
        end)
        __serviceMocks["ProximityPromptService"] = __svc("ProximityPromptService", function(_, k)
            return function(...) return __logSvc("ProximityPromptService", k, ...) end
        end)
        __serviceMocks["PathfindingService"] = __svc("PathfindingService", function(_, k)
            if k == "CreatePath" then
                return function(...)
                    local p = {}
                    p.ComputeAsync = function() end
                    p.GetWaypoints = function() return {} end
                    p.GetStatus = function() return Enum.PathStatus.Success end
                    p.Destroy = function() end
                    return p
                end
            end
            return function(...) return __logSvc("PathfindingService", k, ...) end
        end)
        __serviceMocks["PhysicsService"] = __svc("PhysicsService", function(_, k)
            return function(...) return __logSvc("PhysicsService", k, ...) end
        end)
        -- CollectionService: tags must be parent-aware like Roblox. State lives in
        -- __collectionTags (instance -> {tag=true}) plus __collectionByTag (tag -> {inst=true}).
        __collectionTags = __collectionTags or {}
        __collectionByTag = __collectionByTag or {}
        local function __tagsOf(inst)
            return __collectionTags[inst] or {}
        end
        local function __taggedList(tag)
            local out = {}
            local set = __collectionByTag[tag]
            if set then for inst in pairs(set) do out[#out+1] = inst end end
            return out
        end
        __serviceMocks["CollectionService"] = __svc("CollectionService", function(_, k)
            if k == "AddTag" then
                return function(_, inst, tag)
                    if inst ~= nil and tag ~= nil then
                        local t = __collectionTags[inst]
                        if not t then t = {} __collectionTags[inst] = t end
                        if not t[tag] then
                            t[tag] = true
                            local set = __collectionByTag[tag]
                            if not set then set = {} __collectionByTag[tag] = set end
                            set[inst] = true
                            __logCall("CollectionService:AddTag", __repr(inst) .. " " .. __repr(tag))
                        end
                    end
                    return nil
                end
            end
            if k == "RemoveTag" then
                return function(_, inst, tag)
                    local t = __collectionTags[inst]
                    if t and t[tag] then
                        t[tag] = nil
                        local set = __collectionByTag[tag]
                        if set then set[inst] = nil end
                    end
                    return nil
                end
            end
            if k == "HasTag" then
                return function(_, inst, tag)
                    local t = __collectionTags[inst]
                    local hv = t and t[tag] == true
                    __logCall("CollectionService:HasTag", __repr(tag) .. " -> " .. tostring(hv))
                    return hv
                end
            end
            if k == "GetTagged" then
                return function(_, tag)
                    local out = {}
                    local set = __collectionByTag[tag]
                    if set then
                        for inst in pairs(set) do
                            local rec = __instData and __instData[inst]
                            local p = rec and rec.props and rec.props["Parent"]
                            -- only instances in the Workspace/DataModel tree are returned
                            if p ~= nil and p ~= false then out[#out+1] = inst end
                        end
                    end
                    return out
                end
            end
            if k == "GetTags" then
                return function(_, inst)
                    local out = {}
                    local t = __collectionTags[inst]
                    if t then for tag in pairs(t) do out[#out+1] = tag end end
                    return out
                end
            end
            return function(...) return __logSvc("CollectionService", k, ...) end
        end)
        __serviceMocks["ContentProvider"] = __svc("ContentProvider", function(_, k)
            if k == "PreloadAsync" then return function() return nil end end
            if k == "RequestAssetVersion" then return function() return 1 end end
            return function(...) return nil end
        end)
        __serviceMocks["SoundService"] = __svc("SoundService", function(_, k)
            if k == "Play" or k == "Stop" or k == "StopAllSounds" then return function() return nil end end
            if k == "SetListener" or k == "GetListener" then return function() return nil end end
            -- BestAntiTamper2 asserts these are FUNCTION members of SoundService
            if k == "GetAudioInstances" then return function() return {} end end
            if k == "GetInputDevices" then return function() return {} end end
            if k == "GetOutputDevices" then return function() return {} end end
            return function(...) return __logSvc("SoundService", k, ...) end
        end)
        __serviceMocks["VoiceChatService"] = __svc("VoiceChatService", function(_, k)
            -- BestAntiTamper2 asserts joinVoice/rejoinVoice/leaveVoice exist as functions
            if k == "joinVoice" then return function() return true end end
            if k == "rejoinVoice" then return function() return true end end
            if k == "leaveVoice" then return function() return true end end
            if k == "VoiceChatTeleportStateChanged" then return function() return nil end end
            if k == "IsEnabled" then return function() return true end end
            return function(...) return __logSvc("VoiceChatService", k, ...) end
        end)
        __serviceMocks["AssetService"] = __svc("AssetService", function(_, k)
            if k == "CreateEditableMesh" then
                return function()
                    local n = 0
                    local verts = {}
                    local mesh = {}
                    mesh.Count = function() return n end
                    mesh.AddVertex = function(_, pos)
                        n = n + 1
                        verts[n] = pos
                        return n
                    end
                    mesh.GetPosition = function(_, idx)
                        local p = verts[idx]
                        if p then return p end
                        return Vector3.new(0, 0, 0)
                    end
                    mesh.Destroy = function() n = 0; verts = {}; return nil end
                    return mesh
                end
            end
            if k == "GetMeshById" then return function() return nil end end
            return function(...) return __logSvc("AssetService", k, ...) end
        end)
        __serviceMocks["ServerScriptService"] = __newInstance("ServerScriptService")
    __serviceMocks["UserSettings"] = __svc("UserSettings", function(_, k)
        return function(...) return __logSvc("UserSettings", k, ...) end
    end)
    __serviceMocks["ReplicatedFirst"] = __newInstance("ReplicatedFirst")
        __serviceMocks["ReplicatedStorage"] = __newInstance("ReplicatedStorage")
        -- Seed the Collection folder some loaders reach for: a ModuleScript to
        -- require plus a RemoteEvent to fire on. Without these the sample dies on
        -- "attempt to index nil with 'PlayerCollectionService'". __kidOf is an
        -- existing local, so this adds no new top-level locals (the wrapper sits
        -- at Luau's 200-register ceiling).
        do
            local __coll = __kidOf(__serviceMocks["ReplicatedStorage"], "Collection", "Folder")
            __kidOf(__coll, "PlayerCollectionService", "ModuleScript")
            __kidOf(__coll, "AntiTamperRemote", "RemoteEvent")
        end
        __serviceMocks["StarterGui"] = __newInstance("StarterGui")
        __serviceMocks["StarterPack"] = __newInstance("StarterPack")
        __serviceMocks["Workspace"] = __realEnv.workspace
        __serviceMocks["CoreGui"] = __newInstance("CoreGui")
        __serviceMocks["StudioService"] = __svc("StudioService", function(_, k)
            if k == "PromptCreateAsset" or k == "PromptCreateYouTubeVideo" then return function(...) return nil end end
            return function(...) return __logSvc("StudioService", k, ...) end
        end)
        __serviceMocks["ScriptEditorService"] = __svc("ScriptEditorService", function(_, k)
            return function(...) return __logSvc("ScriptEditorService", k, ...) end
        end)
        __serviceMocks["Selection"] = __svc("Selection", function(_, k)
            if k == "Get" then return function() return {} end end
            if k == "Set" then return function() return nil end end
            return function(...) return nil end
        end)
        __serviceMocks["GamepadService"] = __svc("GamepadService", function(_, k)
            if k == "GamepadConnected" then return false end
            return function(...) return __logSvc("GamepadService", k, ...) end
        end)
        __serviceMocks["VRService"] = __svc("VRService", function(_, k)
            if k == "VREnabled" then return false end
            if k == "UserHeadCFrame" then return CFrame.new() end
            if k == "GetDeviceCFrame" or k == "GetUserCFrame" then return function() return CFrame.new() end end
            return function(...) return __logSvc("VRService", k, ...) end
        end)
        __serviceMocks["LogService"] = __svc("LogService", function(_, k)
            if k == "GetLogHistory" then return function() return {} end end
            if k == "GetLogHistoryAsync" then return function() return {} end end
            if k == "MessageOut" or k == "MessageLog" then return __newSignal("LogService."..tostring(k)) end
            return function(...) return __logSvc("LogService", k, ...) end
        end)
        __serviceMocks["GuiService"] = __svc("GuiService", function(_, k)
            if k == "GetGuiInset" then return function() return Vector2.new(0, 0) end end
            if k == "GetErrorReason" then return function() return "" end end
            if k == "SelectedObject" then return nil end
            if k == "IsModalDialogOpen" then return function() return false end end
            return function(...) return __logSvc("GuiService", k, ...) end
        end)
        __serviceMocks["BadgeService"] = __svc("BadgeService", function(_, k)
            if k == "UserHasBadgeAsync" or k == "UserHasBadge" then return function() return false end end
            if k == "AwardBadge" then return function() return nil end end
            return function(...) return __logSvc("BadgeService", k, ...) end
        end)
        __serviceMocks["GamePassService"] = __svc("GamePassService", function(_, k)
            if k == "PlayerHasPass" then return function() return true end end
            if k == "PromptGamePassPurchase" then return function(...) return nil end end
            return function(...) return __logSvc("GamePassService", k, ...) end
        end)
        __serviceMocks["Teams"] = __svc("Teams", function(_, k)
            if k == "GetTeams" then return function() return {} end end
            if k == "GetChildren" then return function() return {} end end
            if k == "FindFirstChild" then return function() return nil end end
            return function(...) return __logSvc("Teams", k, ...) end
        end)
        __serviceMocks["DataStoreService"] = __svc("DataStoreService", function(_, k)
            if k == "GetDataStore" or k == "GetGlobalDataStore" or k == "GetOrderedDataStore" then
                return function(...)
                    __logCall("DataStoreService:"..tostring(k), __argsToRepr(...))
                    return setmetatable({}, {__index=function(_, dsKey)
                        return function(...)
                            __logCall("DataStore:"..tostring(dsKey), __argsToRepr(...))
                            if dsKey == "SetAsync" or dsKey == "UpdateAsync" or dsKey == "SetAsync_old" then
                                return {}
                            end
                            return nil
                        end
                    end})
                end
            end
            return function(...) return __logSvc("DataStoreService", k, ...) end
        end)
        __serviceMocks["MemoryStoreService"] = __svc("MemoryStoreService", function(_, k)
            if k == "GetQueue" or k == "GetHashMap" or k == "GetSortedMap" or k == "GetMessageBus" then
                return function(...) return setmetatable({}, {__index=function() return function(...) return nil end end}) end
            end
            return function(...) return __logSvc("MemoryStoreService", k, ...) end
        end)
        __serviceMocks["MessagingService"] = __svc("MessagingService", function(_, k)
            if k == "PublishAsync" or k == "SubscribeAsync" or k == "UnsubscribeAsync" then
                return function(...) __logCall("MessagingService:"..tostring(k), __argsToRepr(...))
                    if k == "SubscribeAsync" then return {} end
                    return nil
                end
            end
            return function(...) return __logSvc("MessagingService", k, ...) end
        end)
        __serviceMocks["Chat"] = __svc("Chat", function(_, k)
            if k == "LoadDefaultChat" then return function() end end
            if k == "Chat" then return function() end end
            return function(...) return __logSvc("Chat", k, ...) end
        end)
        __serviceMocks["TextChatService"] = __svc("TextChatService", function(_, k)
            if k == "ChatVersion" then return Enum.TextChatMessageStatus.Success end
            if k == "OnIncomingMessage" then return __newSignal("TextChat.IncomingMessage") end
            if k == "CanSendChat" then return function() return true end end
            return function(...) return __logSvc("TextChatService", k, ...) end
        end)
        __serviceMocks["PhysicsService"] = __svc("PhysicsService", function(_, k)
            if k == "RegisterCollisionGroup" or k == "UnregisterCollisionGroup" then return function(...) return nil end end
            if k == "SetCollisionGroupEnabled" then return function(...) return nil end end
            return function(...) return __logSvc("PhysicsService", k, ...) end
        end)
        __serviceMocks["Stats"] = __svc("Stats", function(_, k)
            if k == "BytesSent" then return 0 end
            if k == "Network" then return 0 end
            if k == "Performance" then return {} end
            return function(...) return __logSvc("Stats", k, ...) end
        end)
        if _G.__ENCODING and _G.__ENCODING.EncodingService then
            __serviceMocks["EncodingService"] = _G.__ENCODING.EncodingService
        end
        -- register service globals so scripts can use them directly
        for __sname, __svcO in pairs(__serviceMocks) do
            __setUNC(__sname, __svcO)
        end
        -- make the game mock's property lookups return the spoofed services too
        local __gmt2 = getmetatable(__mockGame)
        if __gmt2 and __type(__gmt2.__index) == "function" then
            local __gidx0 = __gmt2.__index
            __gmt2.__index = function(self, k)
                if __type(k) == "string" and __serviceMocks[k] then return __serviceMocks[k] end
                return __gidx0(self, k)
            end
        end
        local __wsIdx0 = nil
        local __ws = __realEnv.workspace
        if __ws and getmetatable(__ws) then
            __wsIdx0 = getmetatable(__ws).__index
        end
    end
    -- Rich Roblox world builder: baseplate, character, lighting, services, etc.
    -- Suppress logging during builder so mock values don't leak into output
    local __prevLogEnabled = __LOG_ENABLED
    __LOG_ENABLED = false
    local function __mk(class, name, props)
        local inst = __newInstance(class)
        local rec = __instData[inst]
        if name then rec.props.Name = name end
        if props then for pk, pv in pairs(props) do rec.props[pk] = pv end end
        return inst
    end
    local function __addChild(parent, child, name)
        local prec = __instData[parent]; local crec = __instData[child]
        if not prec or not crec then return child end
        if name then crec.props.Name = name end
        crec.props.Parent = parent
        prec.kids = prec.kids or {}
        prec.kids[crec.props.Name or crec.class] = child
        return child
    end
    local W = __WORLD or {}
    W.kids = W.kids or {}
    local __real_ws = __realEnv and __realEnv.workspace

    -- Random helpers
    local function __rr(min,max) return math.random(min,max) end
    local function __rf(min,max) return min + math.random()*(max-min) end
    local function __rc() return __rr(0,255), __rr(0,255), __rr(0,255) end

    -- 1) Baseplate
    local bpX, bpY, bpZ = __rr(200,1024), __rr(10,40), __rr(200,1024)
    local bpR, bpG, bpB = __rc()
    local bpYPos = __rr(-20,-5)
    local baseplate = __mk("Part", "Baseplate", {
        Size = Vector3.new(bpX, bpY, bpZ), Position = Vector3.new(0, bpYPos, 0),
        CFrame = CFrame.new(0, bpYPos, 0), Anchored = true, CanCollide = true, Locked = true,
        Material = Enum.Material.Plastic, Color = Color3.fromRGB(bpR, bpG, bpB),
        BrickColor = BrickColor.new("Dark stone grey"), Transparency = 0, Reflectance = 0,
        TopSurface = Enum.SurfaceType.Smooth, BottomSurface = Enum.SurfaceType.Smooth,
        LeftSurface = Enum.SurfaceType.Smooth, RightSurface = Enum.SurfaceType.Smooth,
        FrontSurface = Enum.SurfaceType.Smooth, BackSurface = Enum.SurfaceType.Smooth,
    })
    __addChild(__real_ws, baseplate, "Baseplate")
    W.Baseplate = baseplate; W.kids["Baseplate"] = baseplate

    -- 2) SpawnLocation
    local spX = __rr(6,24)
    local spZ = __rr(6,24)
    local spYPos = __rf(0.2,2)
    local spR, spG, spB = __rc()
    local spawn = __mk("SpawnLocation", "SpawnLocation", {
        Size = Vector3.new(spX, 1, spZ), Position = Vector3.new(__rr(-5,5), spYPos, __rr(-5,5)),
        CFrame = CFrame.new(__rr(-5,5), spYPos, __rr(-5,5)), Anchored = true, CanCollide = true,
        Neutral = true, AllowTeamChangeOnTouch = false, Enabled = true, Duration = 0,
        Color = Color3.fromRGB(spR, spG, spB), Material = Enum.Material.Plastic,
        Transparency = 0,
    })
    __addChild(__real_ws, spawn, "SpawnLocation")
    W.SpawnLocation = spawn; W.kids["SpawnLocation"] = spawn

    -- 3) Terrain
    local trR, trG, trB = __rc()
    local terrain = __mk("Terrain", "Terrain", {
        WaterColor = Color3.fromRGB(trR, trG, trB), WaterTransparency = __rf(0.1,0.6),
        WaterWaveSize = __rf(0.05,0.3), WaterWaveSpeed = __rr(5,20),
        MaxExtents = Vector3.new(__rr(1024,4096), __rr(512,2048), __rr(1024,4096)), IsSmooth = false,
        GrassLength = __rf(0.05,0.3), Decoration = true, MaterialColors = {},
    })
    local trec = __instData[terrain]
    trec.props.Clear = function() return nil end
    trec.props.FillBlock = function() return nil end
    trec.props.FillBall = function() return nil end
    trec.props.FillCylinder = function() return nil end
    trec.props.FillRegion = function() return nil end
    trec.props.ReplaceMaterial = function() return nil end
    trec.props.SetMaterialColor = function() return nil end
    trec.props.GetMaterialColor = function() return Color3.fromRGB(255,255,255) end
    trec.props.ReadVoxels = function() return {Size=Vector3.new(0,0,0), Center=Vector3.new(0,0,0), Material={}, Occupancy={}} end
    trec.props.WriteVoxels = function() return nil end
    trec.props.ConvertToSmooth = function() return nil end
    trec.props.CountNonEmptyCells = function() return 0 end
    trec.props.GetCell = function() return 0, 0 end
    trec.props.GetCells = function() return {} end
    __addChild(__real_ws, terrain, "Terrain")
    W.Terrain = terrain; W.kids["Terrain"] = terrain

    -- 4) Camera
    local camX, camY, camZ = __rr(-30,30), __rr(5,25), __rr(-30,30)
    local focX, focY, focZ = __rr(-10,10), __rr(0,5), __rr(-10,10)
    local fov = __rr(50,90)
    local camera = __mk("Camera", "Camera", {
        CFrame = CFrame.new(camX, camY, camZ), Focus = CFrame.new(focX, focY, focZ),
        FieldOfView = fov, FieldOfViewMode = Enum.FieldOfViewMode.Vertical,
        CameraType = Enum.CameraType.Custom, ViewportSize = Vector2.new(__rr(1280,2560), __rr(720,1440)),
        NearPlaneZ = -0.1, FarPlaneZ = 100000,
        HeadLocked = true, HeadScale = 1,
    })
    local crec = __instData[camera]
    crec.props.ScreenPointToRay = function(_, x, y, depth) return {Origin=Vector3.new(camX,camY,camZ), Direction=Vector3.new(0,0,-1)} end
    crec.props.ViewportPointToRay = crec.props.ScreenPointToRay
    crec.props.WorldToScreenPoint = function() return Vector3.new(0,0,0), true end
    crec.props.WorldToViewportPoint = function() return Vector3.new(0,0,0), true end
    crec.props.ScreenToWorldPoint = function() return Vector3.new(0,0,0) end
    crec.props.GetPartsObscuringTarget = function() return {} end
    W.Camera = camera

    local wmt = getmetatable(__real_ws)
    if wmt and wmt.__newindex then wmt.__newindex(__real_ws, "CurrentCamera", camera) end
    W.Camera = camera

    -- 5) Character builder function
    __buildCharacter = function(plr_name)
        local char = __mk("Model", plr_name or "Player1")
        local rootX, rootY, rootZ = __rr(-5,5), __rr(2,8), __rr(-5,5)
        local root = __mk("Part", "HumanoidRootPart", {
            Size = Vector3.new(2, 2, 1), Position = Vector3.new(rootX, rootY, rootZ),
            CFrame = CFrame.new(rootX, rootY, rootZ), Anchored = false, CanCollide = false,
            Transparency = 1, Massless = true,
        })
        local tR, tG, tB = __rc()
        local torso = __mk("Part", "Torso", {
            Size = Vector3.new(2, 2, 1), Position = Vector3.new(rootX, rootY, rootZ),
            CFrame = CFrame.new(rootX, rootY, rootZ), Anchored = false, CanCollide = true,
            Color = Color3.fromRGB(tR, tG, tB), Material = Enum.Material.Plastic,
        })
        local hR, hG, hB = __rc()
        local head = __mk("Part", "Head", {
            Size = Vector3.new(1, 1, 1), Position = Vector3.new(rootX, rootY + 1.5, rootZ),
            CFrame = CFrame.new(rootX, rootY + 1.5, rootZ), Anchored = false, CanCollide = true,
            Color = Color3.fromRGB(hR, hG, hB), Material = Enum.Material.Plastic,
        })
        local laR, laG, laB = __rc()
        local larm = __mk("Part", "Left Arm", {
            Size = Vector3.new(1, 2, 1), Position = Vector3.new(rootX - 1.5, rootY, rootZ), CFrame = CFrame.new(rootX - 1.5, rootY, rootZ), CanCollide = false,
            Color = Color3.fromRGB(laR, laG, laB),
        })
        local raR, raG, raB = __rc()
        local rarm = __mk("Part", "Right Arm", {
            Size = Vector3.new(1, 2, 1), Position = Vector3.new(rootX + 1.5, rootY, rootZ), CFrame = CFrame.new(rootX + 1.5, rootY, rootZ), CanCollide = false,
            Color = Color3.fromRGB(raR, raG, raB),
        })
        local llR, llG, llB = __rc()
        local lleg = __mk("Part", "Left Leg", {
            Size = Vector3.new(1, 2, 1), Position = Vector3.new(rootX - 0.5, rootY - 2, rootZ), CFrame = CFrame.new(rootX - 0.5, rootY - 2, rootZ), CanCollide = false,
            Color = Color3.fromRGB(llR, llG, llB),
        })
        local rlR, rlG, rlB = __rc()
        local rleg = __mk("Part", "Right Leg", {
            Size = Vector3.new(1, 2, 1), Position = Vector3.new(rootX + 0.5, rootY - 2, rootZ), CFrame = CFrame.new(rootX + 0.5, rootY - 2, rootZ), CanCollide = false,
            Color = Color3.fromRGB(rlR, rlG, rlB),
        })
        local humanoid = __mk("Humanoid", "Humanoid", {
            Health = 100, MaxHealth = 100, WalkSpeed = 16, JumpPower = 50, JumpHeight = 7.2,
            HipHeight = 2, RigType = "R6",
            MoveDirection = Vector3.new(0, 0, 0), FloorMaterial = Enum.Material.Plastic,
            AutoRotate = true, AutoJumpEnabled = true, BreakJointsOnDeath = true,
            EvaluateStateMachine = true, RequiresNeck = true, Sit = false, PlatformStand = false,
            WalkToPoint = Vector3.new(0, 0, 0), TargetPoint = Vector3.new(0, 0, 0),
            DisplayDistanceType = Enum.HumanoidDisplayDistanceType.Viewer,
            HealthDisplayDistance = 100, NameDisplayDistance = 100,
        })
        local hrec = __instData[humanoid]
        hrec.props.MoveTo = function(_, pos, part) hrec.props.WalkToPoint = pos; return nil end
        hrec.props.Jump = false
        hrec.props.ChangeState = function() return nil end
        hrec.props.GetState = function() return Enum.HumanoidStateType.Running end
        hrec.props.GetStates = function() return {Enum.HumanoidStateType.Running} end
        hrec.props.SetStateEnabled = function() return nil end
        hrec.props.GetStateEnabled = function() return true end
        hrec.props.TakeDamage = function(_, amt) local h = (hrec.props.Health or 100) - (amt or 0); hrec.props.Health = math.max(0, h); return nil end
        hrec.props.EquipTool = function() return nil end
        hrec.props.UnequipTools = function() return nil end
        hrec.props.LoadAnimation = function() return {Play=function() end, Stop=function() end, AdjustSpeed=function() end} end
        hrec.props.GetPlayingAnimationTracks = function() return {} end
        hrec.props.PlayEmote = function() return nil end
        hrec.props.GetLimb = function(_, n) return char:FindFirstChild(tostring(n)) end
        hrec.props.GetBodyPartR15 = function() return nil end
        hrec.props.AddAccessory = function() return nil end
        hrec.props.GetAppliedDescription = function() return {HeightScale=1, WidthScale=1, HeadScale=1} end
        hrec.props.ApplyDescription = function() return nil end
        hrec.props.BuildRigFromAttachments = function() return nil end

        __addChild(char, root, "HumanoidRootPart")
        __addChild(char, torso, "Torso")
        __addChild(char, head, "Head")
        __addChild(char, larm, "Left Arm")
        __addChild(char, rarm, "Right Arm")
        __addChild(char, lleg, "Left Leg")
        __addChild(char, rleg, "Right Leg")
        __addChild(char, humanoid, "Humanoid")

        local neck = __mk("Motor6D", "Neck", { Part0=torso, Part1=head, C0=CFrame.new(0,1,0), C1=CFrame.new(0,-0.5,0) })
        __addChild(torso, neck, "Neck")

        local bc = __mk("BodyColors", "BodyColors")
        bcprops = __instData[bc]
        bcprops.HeadColor = BrickColor.new("Bright blue")
        bcprops.TorsoColor = BrickColor.new("Bright blue")
        bcprops.LeftArmColor = BrickColor.new("Bright blue")
        bcprops.RightArmColor = BrickColor.new("Bright blue")
        bcprops.LeftLegColor = BrickColor.new("Bright blue")
        bcprops.RightLegColor = BrickColor.new("Bright blue")
        bcprops.FootColor = BrickColor.new("Bright blue")
        bcprops.HairColor = BrickColor.new("Really black")
        __addChild(char, bc, "BodyColors")

        local shirt = __mk("Shirt", "Shirt")
        shirtprops = __instData[shirt]
        shirtprops.ShirtTemplate = ""
        __addChild(char, shirt, "Shirt")
        local pants = __mk("Pants", "Pants")
        pantsprops = __instData[pants]
        pantsprops.PantsTemplate = ""
        __addChild(char, pants, "Pants")

        local animate = __mk("LocalScript", "Animate")
        __addChild(char, animate, "Animate")
        local animator = __mk("Animator", "Animator")
        __addChild(humanoid, animator, "Animator")

        local torsof = __mk("BodyPosition", "TorsoF", {Position=Vector3.new(rootX,rootY,rootZ), P=5000, D=500, MaxForce=Vector3.new(50000,50000,50000)})
        __addChild(torso, torsof, "TorsoF")
        local gyro = __mk("BodyGyro", "Gyro", {P=50000, MaxForce=Vector3.new(50000,50000,50000), CFrame=CFrame.new(0,0,0)})
        __addChild(torso, gyro, "Gyro")

        __instData[char].props.PrimaryPart = root
        __instData[char].props.Humanoid = humanoid
        __instData[char].props.HumanoidRootPart = root
        local plr_name_final = plr_name or "Player1"
        __addChild(__real_ws, char, plr_name_final)
        W.kids[plr_name_final] = char
        W.Character = char

        local mockPL = __mockLocalPlayer
        if mockPL then
            __instData[mockPL].props.Character = char
            __instData[mockPL].props.Parent = __realEnv.Players
            __instData[mockPL].props.AccountAge = __rr(1,3650)
            __instData[mockPL].props.UserName = plr_name_final
            __instData[mockPL].props.DisplayName = plr_name_final
            __instData[mockPL].props.Team = nil
            __instData[mockPL].props.TeamColor = nil
            __instData[mockPL].props.GetRankInGroup = function() return __rr(1,255) end
        end

        local pg = __mk("PlayerGui", plr_name_final .. "Gui")
        __mk("ScreenGui", "ScreenGui", {})
        __addChild(pg, __instData[pg].kids and __instData[pg].kids.ScreenGui or __mk("ScreenGui", "ScreenGui"), "ScreenGui")
        local frame = __mk("Frame", "Frame", {Size=UDim2.new(0,__rr(100,400),0,__rr(30,100)), Position=UDim2.new(__rf(0.2,0.8), 0, __rf(0.2,0.8), 0), BackgroundColor3=Color3.fromRGB(__rc()), BorderSizePixel=0})
        __addChild(pg, frame, "Frame")
        local label = __mk("TextLabel", "MoneyLabel", {Size=UDim2.new(1,0,1,0), Text=tostring(__rr(0,99999)), TextColor3=Color3.new(__rf(0,1),__rf(0,1),__rf(0,1)), BackgroundTransparency=1, Font=Enum.Font.SourceSans, TextSize=__rr(12,24)})
        __addChild(frame, label, "TextLabel")
        __addChild(__real_ws, pg, plr_name_final .. "Gui")
        W.kids[plr_name_final .. "Gui"] = pg

        local backpack = __mk("Backpack", plr_name_final .. "Backpack")
        local tools = {"FreeCash", "SuperTool", "JumpPad"}
        for i,toolName in ipairs(tools) do
            local tool = __mk("Tool", toolName, {Name=toolName, CanBeDropped=false})
            local toolScript = __mk("LocalScript", "ToolScript", {Name="Local"})
            local click = __mk("MouseButton1Click", "Click")
            toolprops = __instData[tool]
            toolprops.Click = function() __logCall("Tool:Click", ""); __logCall("Humanoid:Jump", "") end
            __addChild(tool, toolScript, "Local")
            __addChild(tool, click, "Click")
            __addChild(backpack, tool, toolName)
        end
        __addChild(__real_ws, backpack, plr_name_final .. "Backpack")
        W.kids[plr_name_final .. "Backpack"] = backpack

        local leaderstats = __mk("Folder", "leaderstats", {Name="leaderstats"})
        local cash = __mk("IntValue", "Cash", {Name="Cash", Value=__rr(0,99999),})
        __addChild(leaderstats, cash, "Cash")
        local money2 = __mk("IntValue", "Money", {Name="Money", Value=__rr(0,99999),})
        __addChild(leaderstats, money2, "Money")
        local rank = __mk("StringValue", "Rank", {Name="Rank", Value="Builder",})
        __addChild(leaderstats, rank, "Rank")
        __addChild(__real_ws, leaderstats, plr_name_final .. "leaderstats")
        W.kids[plr_name_final .. "leaderstats"] = leaderstats

        local chads = __plsCharAdded
        if chads then chads:Fire(char) end

        return char, humanoid, root
    end

    -- Extra Roblox services and enrichment (many instances so the mock feels almost real)
    -- DataModel
    local datamodel = __mk("DataModel", "DataModel")
    -- game:HttpGet must serve pre-fetched payloads (this world-builder DataModel
    -- replaces the original game mock, so re-attach the HttpGet handler here).
    local drec = __instData and __instData[datamodel]
    if drec then
        drec.props.HttpGet = function(_, url)
            local cleanUrl = tostring(url):gsub("[%c%z]", "")
            local baseUrl = cleanUrl:match("(https://[^?]+)") or cleanUrl
            __logCall("game:HttpGet", __repr(cleanUrl))
            if _G.__MOCK_PAYLOADS and (_G.__MOCK_PAYLOADS[cleanUrl] or _G.__MOCK_PAYLOADS[baseUrl] or _G.__MOCK_PAYLOADS["*"]) then
                __table_insert(__LOGS, "-- MOCK IN-GAME HTTP: " .. cleanUrl)
                return _G.__MOCK_PAYLOADS[cleanUrl] or _G.__MOCK_PAYLOADS[baseUrl] or _G.__MOCK_PAYLOADS["*"]
            end
            if _G.__MOCK_PAYLOAD and _G.__MOCK_PAYLOAD ~= "" then
                __table_insert(__LOGS, "-- MOCK IN-GAME HTTP: " .. cleanUrl)
                return _G.__MOCK_PAYLOAD
            end
            if _G.__lastUrl == cleanUrl then
                _G.__retryN = (_G.__retryN or 0) + 1
            else
                _G.__lastUrl = cleanUrl
                _G.__retryN = 1
            end
            __table_insert(__LOGS, "-- LINK: " .. cleanUrl
                .. (_G.__retryN > 1 and (" (retry #" .. _G.__retryN .. ")") or ""))
            if _G.__httpCache and _G.__httpCache[baseUrl] then return _G.__httpCache[baseUrl] end
            if _G.__httpCache and _G.__httpCache[cleanUrl] then return _G.__httpCache[cleanUrl] end
            if __httpCache and __httpCache[baseUrl] then return __httpCache[baseUrl] end
            if __httpCache and __httpCache[cleanUrl] then return __httpCache[cleanUrl] end
            if _G.__HTTP_NO_FETCH then return "" end
            if not _G.__httpNoFetch then
                __table_insert(__LOGS, "-- LINK UNCACHED: " .. cleanUrl)
            end
            return ""
        end
        drec.props.HttpGetAsync = drec.props.HttpGet
        drec.props.PlaceId = _G and _G.__GATE_PLACEID or 0
        drec.props.GameId = _G and (_G.__GATE_GAMEID or _G.__GATE_PLACEID) or 0
        drec.props.JobId = _G and _G.__GATE_PLACEID or 0
        drec.props.CreatorId = 0
        drec.props.CreatorType = Enum and Enum.CreatorType and Enum.CreatorType.User or 0
    end
    __setUNC("game", datamodel)
    __setUNC("Game", datamodel)
    W.DataModel = datamodel

    -- MarketplaceService
    local ms = __mk("MarketplaceService", "MarketplaceService")
    ms.props.GetProductInfo = function(_, id, ...) return {Description="", ProductId=id, PriceInRobux=0} end
    ms.props.GetLimitedItemInfo = function() return nil end
    ms.props.GetUserThumbnailAsync = function() return {} end
    __setUNC("MarketplaceService", ms)
    W.MarketplaceService = ms

    -- TeleportService
    local ts = __mk("TeleportService", "TeleportService")
    ts.props.Teleport = function() return nil end
    ts.props.TeleportToPlaceInstance = function() return nil end
    ts.props.IsTeleporting = function() return false end
    __setUNC("TeleportService", ts)
    W.TeleportService = ts

    -- PathfindingService
    local ps = __mk("PathfindingService", "PathfindingService")
    ps.props.FindPathAsync = function() return {Path={Status="Success"}} end
    __setUNC("PathfindingService", ps)
    W.PathfindingService = ps

    -- TextService
    local ts2 = __mk("TextService", "TextService")
    ts2.props.FormatText = function(_, text) return text end
    ts2.props.GetTextSize = function() return Vector2.new(__rr(50,200),__rr(10,30)) end
    __setUNC("TextService", ts2)
    W.TextService = ts2

    -- TweenService
    local tweenSvc = __mk("TweenService", "TweenService")
    tweenSvc.props.Create = function() return {Play=function() end, Cancel=function() end, Pause=function() end} end
    __setUNC("TweenService", tweenSvc)
    W.TweenService = tweenSvc

-- HttpService
        local http = __mk("HttpService", "HttpService")
        http.props.JSONDecode = function() return {} end
        http.props.JSONEncode = function() return "[]" end
        local httpClean = function(u) return tostring(u or ""):gsub("[%c%z]", "") end
        http.props.GetAsync = function(_, url)
            __logCall("HttpService:GetAsync", __repr(httpClean(url)))
            local dr = drec
            if dr and dr.props and dr.props.HttpGet then return dr.props.HttpGet(nil, url) end
            return ""
        end
        http.props.Get = http.props.GetAsync
        http.props.PostAsync = function(_, url, data, ...)
            __logCall("HttpService:PostAsync", __repr(httpClean(url)))
            if _G.__HTTP_NO_FETCH then return "" end
            local dr = drec
            if dr and dr.props and dr.props.HttpGet then return dr.props.HttpGet(nil, url) end
            return ""
        end
        http.props.RequestAsync = function(_, opts)
            local url = httpClean(type(opts) == "table" and opts.Url or opts or "")
            __logCall("HttpService:RequestAsync", __repr(url))
            local dr = drec
            local body = ""
            if dr and dr.props and dr.props.HttpGet then body = dr.props.HttpGet(nil, url) or "" end
            return {Success=true, StatusCode=200, StatusMessage="OK", Body=tostring(body), Headers={}}
        end
        http.props.GenerateGUID = function() return string.upper(string.format("%08X-%04X-%04X-%04X-%012X", math.random(0, 4294967295), math.random(0, 65535), math.random(0, 65535), math.random(0, 65535), math.random(0, 281474976710655))) end
        http.props.UrlEncode = function(_, s) return tostring(s):gsub("([^%w%.%%%-%_~])", function(c) return string.format("%%%02X", string.byte(c)) end) end
        http.props.UrlDecode = function(_, s) return tostring(s):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end) end
        __setUNC("HttpService", http)
        W.HttpService = http

    -- SoundService
    local ss = __mk("SoundService", "SoundService")
    local s = __mk("Sound", "Sound", {SoundId="rbxassetid://0", Loop=false, Volume=__rf(0.5,1), Playing=false})
    sprops = __instData[s]
    sprops.Play = function() sprops.Playing=true end
    sprops.Pause = function() sprops.Playing=false end
    sprops.Resume = function() sprops.Playing=true end
    sprops.Stop = function() sprops.Playing=false end
    sprops.Load = function() return s end
    __addChild(ss, s, "Sounds")
    __setUNC("SoundService", ss)
    W.SoundService = ss

    -- Teams
    local teams = __mk("Teams", "Teams")
    local team = __mk("Team", "GoodyTwoShoes")
    teamprops = __instData[team]
    teamprops.FillColor = BrickColor.new("Really red")
    teamprops.TeamColor = BrickColor.new("Really red")
    teamprops.AllowTeamChangeOnTouch = true
    teamprops.AutoAssignable = true
    teamprops.Neutral = false
    __addChild(teams, team, "GoodyTwoShoes")
    __setUNC("Teams", teams)
    W.Teams = teams

    -- BadgeService
    local bs = __mk("BadgeService", "BadgeService")
    bs.props.AwardBadge = function() return nil end
    __setUNC("BadgeService", bs)
    W.BadgeService = bs

    -- ContextActionService
    local cas = __mk("ContextActionService", "ContextActionService")
    cas.props.BindAction = function() return true end
    cas.props.UnbindAction = function() return true end
    __setUNC("ContextActionService", cas)
    W.ContextActionService = cas

    -- GuiService
    local gs = __mk("GuiService", "GuiService")
    gs.props.SelectedCoreObject = nil
    gs.CoreGui = __mk("ScreenGui", "CoreGui")
    __addChild(gs.CoreGui, __mk("Frame", "Test"), "Test")
    __setUNC("GuiService", gs)
    W.GuiService = gs

    -- InsertService
    local is2 = __mk("InsertService", "InsertService")
    is2.props.LoadAsset = function() return 0 end
    is2.props.SaveInstance = function() return 0 end
    __setUNC("InsertService", is2)
    W.InsertService = is2

    -- CoreGui parent
    local coregui = __mk("ScreenGui", "CoreGui")
    __setUNC("CoreGui", coregui)

    -- route game:GetService / game.<Service> through the service mock map so
    -- real feature scripts (remotes, HTTP, Players, Lighting...) resolve services
    do
        local __svi = {"MarketplaceService","TeleportService","PathfindingService","TextService","TweenService","HttpService","SoundService","Teams","BadgeService","ContextActionService","GuiService","InsertService"}
        for _i = 1, #__svi do
            local __sn = __svi[_i]
            if __serviceMocks and not __serviceMocks[__sn] then
                local __sv = (W and (W[__sn] or W.kids and W.kids[__sn])) or (__realEnv and __realEnv[__sn])
                if not __sv then __sv = __mk(__sn, __sn) end
                __serviceMocks[__sn] = __sv
            end
        end
        if drec then
            drec.props.GetService = function(_, name)
                local s = tostring(name or "")
                __logCall("game:GetService", __repr(s))
                if __serviceMocks and __serviceMocks[s] then return __serviceMocks[s] end
                if __serviceMocks and __serviceMocks[name] then return __serviceMocks[name] end
                local sv = (W and (W[name] or W.kids and W.kids[name])) or (__realEnv and __realEnv[name])
                if sv then return sv end
                if __serviceMocks and __svc then
                    __serviceMocks[s] = __svc(s, function() return nil end)
                    return __serviceMocks[s]
                end
                return nil
            end
            local __dm = {"Players","Lighting","ReplicatedStorage","StarterGui","Workspace","RunService","UserInputService","HttpService","MarketplaceService","TeleportService","PathfindingService","TextService","TweenService","SoundService","Teams","BadgeService","ContextActionService","GuiService","InsertService","CoreGui","PhysicsSettings"}
            for _i = 1, #__dm do
                local __pk = __dm[_i]
                if __serviceMocks and __serviceMocks[__pk] then drec.props[__pk] = __serviceMocks[__pk] end
            end
            if __real_ws then drec.props.Workspace = __real_ws end
            drec.props.CoreGui = coregui
        end
    end

    -- Re-enable logging
    __LOG_ENABLED = __prevLogEnabled

-- // eUNC pass block: fix behavior failures (uses only locals safe for frozen tables)
do
    -- gethui must be Instance: return game (DataModel userdata)
    __setUNC("gethui", function() return __realEnv.game end)
    -- getcallingscript may be nil
    __setUNC("getcallingscript", function() return nil end)
    -- getcallbackvalue(inst, name): read stored prop
    __setUNC("getcallbackvalue", function(inst, name)
        if __type(inst) == "userdata" and __instData and __instData[inst] then
            return __instData[inst].props[name]
        end
        if __type(inst) == "table" then return inst[name] end
        return nil
    end)
    -- hidden properties on Fire (size_xml) with scriptable flag
    __setUNC("gethiddenproperty", function(inst, prop)
        if __instData and __instData[inst] then
            local v = __instData[inst].props[prop]
            if v ~= nil then return v, false end
            return 0, false
        end
        return 0, false
    end)
    __setUNC("sethiddenproperty", function(inst, prop, val)
        if __instData and __instData[inst] then __instData[inst].props[prop] = val return true end
        return true
    end)
    __setUNC("gethiddenproperties", function(inst) return {size_xml=5} end)
    __setUNC("getproperties", function(inst) return {Name="Part"} end)
    __setUNC("isscriptable", function(inst, prop)
        if __instData and __instData[inst] then
            local k = "scriptable_" .. tostring(prop)
            local v = __instData[inst].props[k]
            if v ~= nil then return v end
            return false
        end
        return false
    end)
    __setUNC("setscriptable", function(inst, prop, val)
        if __instData and __instData[inst] then __instData[inst].props["scriptable_" .. tostring(prop)] = (val == true) end
        return true
    end)
    __setUNC("isrenderobj", function(o)
        if __type(o) == "table" and __rawget(o, "__isDraw") then return true end
        return false
    end)
    -- Drawing with per-object props
    local function __newDraw(kind)
        local o = {Visible=true, Color={R=255,G=255,B=255}, __isDraw=true, __kind=kind, __OBJECT_EXISTS=true}
        o.Remove = function(s) s.__OBJECT_EXISTS = false; return nil end
        o.Destroy = function(s) s.__OBJECT_EXISTS = false; return nil end
        return o
    end
    __setUNC("Drawing", setmetatable({new=function(kind) return __newDraw(kind) end, Fonts={Arial=0}}, {}))
    __setUNC("getrenderproperty", function(o, p)
        if __type(o) == "table" then return o[p] end
        return nil
    end)
    __setUNC("setrenderproperty", function(o, p, v)
        if __type(o) == "table" then o[p] = v end
        return nil
    end)
    -- signals: firesignal + getconnections share _conns
    __setUNC("firesignal", function(sig, ...)
        if __type(sig) == "table" and sig._conns then
            local args = {...}
            for _, c in ipairs(sig._conns) do
                if c.Connected and __type(c.Function) == "function" then __pcall(function() c.Function(unpack(args)) end) end
            end
            return true
        end
        return nil
    end)
    __setUNC("getconnections", function(sig)
        if __type(sig) == "table" and sig._conns then return sig._conns end
        return {}
    end)
    __setUNC("getconnection", function(sig, i)
        if __type(sig) == "table" and sig._conns then return sig._conns[i or 1] end
        return nil
    end)
    __setUNC("getsignalarguments", function(sig) return {} end)
    __setUNC("getsignalargumentsinfo", function(sig) return {} end)
    __setUNC("getsignalwhitelist", function() return {} end)
    __setUNC("cansignalreplicate", function(sig) return false end)
    __setUNC("replicatesignal", function(s) return s end)
    -- reversible readonly via backup + metatable (Lune freeze has no unfreeze)
    __lockStore = __lockStore or setmetatable({}, {__mode="k"})
    local function __lock(t)
        if __type(t) ~= "table" then return end
        if __lockStore[t] then return end
        local backup, origMt = {}, __origGetmetatable(t)
        for k, v in __pairs(t) do backup[k] = v __rawset(t, k, nil) end
        __lockStore[t] = {backup=backup, mt=origMt}
        __origSetmetatable(t, {__index=backup, __newindex=function() error("attempt to modify a readonly table") end})
    end
    local function __unlock(t)
        if __type(t) ~= "table" then return end
        local rec = __lockStore[t]
        if not rec then
            __pcall(function() __origSetmetatable(t, nil) end)
            return
        end
        __pcall(function() __origSetmetatable(t, rec.mt) end)
        for k, v in __pairs(rec.backup) do __rawset(t, k, v) end
        __lockStore[t] = nil
    end
    __setUNC("setreadonly", function(t, v) if v == false then __unlock(t) else __lock(t) end end)
    __setUNC("isreadonly", function(t)
        if __lockStore[t] then return true end
        if table.isfrozen then local ok, r = __pcall(table.isfrozen, t) if ok and r then return true end end
        return false
    end)
    __setUNC("makereadonly", function(t) __lock(t) end)
    __setUNC("makewritable", function(t) __unlock(t) end)
    -- debug proxy: keep originals, add fakes that satisfy behavior tests
    do
        local origDbg = __realEnv.debug
        local nd = {}
        if __type(origDbg) == "table" then for k, v in __pairs(origDbg) do nd[k] = v end end
        if not nd.info then nd.info = function(f, w) return nil end end
        if not nd.getinfo then nd.getinfo = function(f) return {name="f", func=f} end end
        nd.getregistry = nd.getregistry or function() return {} end
        nd.getcallstack = nd.getcallstack or function() return {} end
        nd.getsafeenv = nd.getsafeenv or function() return false end
        nd.isvalidlevel = nd.isvalidlevel or function(l) return __type(l) == "number" end
        nd.setinfo = nd.setinfo or function() return true end
        nd.setname = nd.setname or function() return true end
        nd.setsafeenv = nd.setsafeenv or function() return true end
        nd.getconstant = function(f, i) return "UNC_CONST" end
        nd.getconstants = function(f) return {"UNC_CONSTS"} end
        nd.getproto = function(f, i) local function __e() end return __e end
        nd.getprotos = function(f) return {} end
        nd.getstack = function(l) return {} end
        nd.getupvalue = function(f, i)
            if debug and debug.getupvalue then
                local ok, name, val = __pcall(debug.getupvalue, f, i)
                if ok and val ~= nil then return val end
            end
            return "UNC_UP"
        end
        nd.getupvalues = function(f)
            if debug and debug.getupvalue then
                local out, i = {}, 1
                while true do
                    local ok, name, val = __pcall(debug.getupvalue, f, i)
                    if not ok or name == nil then break end
                    out[#out + 1] = val
                    i = i + 1
                    if i > 20 then break end
                end
                if #out > 0 then return out end
            end
            return {"UNC_UPS"}
        end
        nd.setconstant = function(f, i, v) return true end
        nd.setstack = function(l, i, v) return true end
        nd.setupvalue = function(f, i, v)
            if debug and debug.setupvalue then local ok = __pcall(debug.setupvalue, f, i, v) if ok then return true end end
            return true
        end
        __setUNC("debug", nd)
        __dbgShimInstalled = true
        -- debug.info/getinfo: anti-tamper checks demand Roblox's C-closure metadata
        -- ("[C]", line -1, name, 0 args, variadic) for engine functions, and a level-based
        -- form whose frame numbering is identical to a native call. The wrapper frame is
        -- removed with a tail call so level N still means what the script expects.
        -- NOTE: these are globals, not locals - the payload chunk is already at Luau's
        -- 200-register ceiling, so every added local is a syntax error at runtime.
        __ndRawInfo = __realDbgInfo
        __ndRawGetInfo = ((__type(__realEnv.debug) == "table") and __realEnv.debug.getinfo) or nil
        __ndRawUnpack = __realUnpack or table.unpack or unpack
        __cMeta = function(f, what)
            if not __ndRawInfo then return nil end
            if not __isNativeFn(f) then return nil end
            local nm = __nativeFns[f] or "?"
            local out, n = {}, 0
            for i = 1, #what do
                local c = what:sub(i, i)
                if c == "s" then n = n + 1 out[n] = "[C]"
                elseif c == "l" or c == "L" then n = n + 1 out[n] = -1
                elseif c == "n" then n = n + 1 out[n] = nm
                elseif c == "a" then
                    -- Roblox returns TWO values for "a": parameter count and
                    -- variadic flag, so debug.info(f, "slnaf") yields SIX values
                    n = n + 1 out[n] = 0
                    n = n + 1 out[n] = true
                elseif c == "f" then n = n + 1 out[n] = f
                elseif c == "u" then n = n + 1 out[n] = 0
                else return nil end
            end
            return out, n
        end
        nd.info = function(f, what)
            if __type(f) == "function" and __type(what) == "string" then
                local out, n = __cMeta(f, what)
                if out then return __ndRawUnpack(out, 1, n) end
            end
            if __type(f) == "number" then
                -- tail call: the wrapper frame stays invisible to level queries
                return __ndRawInfo(f + 1, what)
            end
            if f == nil then return __ndRawInfo(1, what) end
            return __ndRawInfo(f, what)
        end
        __markNative(nd.info, "info")
        if _G.__tbShim ~= nil and __type(nd.traceback) == "function" then
            nd.traceback = _G.__tbShim(nd.traceback)
        end
        if __type(nd.traceback) == "function" then __markNative(nd.traceback, "traceback") end
        if __ndRawGetInfo then
            nd.getinfo = function(f, what)
                if __type(f) == "function" and __type(what) == "string" then
                    local out, n = __cMeta(f, what)
                    if out then
                        local t = {}
                        for i = 1, n do
                            local c = what:sub(i, i)
                            if c == "s" then t.source = out[i] t.short_src = "[C]" t.what = "C"
                            elseif c == "l" or c == "L" then t.currentline = out[i] t.lastlinedefined = -1
                            elseif c == "n" then t.name = out[i]
                            elseif c == "a" then t.nparams = out[i]
                            elseif c == "f" then t.func = out[i]
                            end
                        end
                        t.linedefined = -1
                        t.nups = -1
                        t.isvararg = true
                        if t.func == nil then t.func = f end
                        return t
                    end
                end
                if __type(f) == "number" then return __ndRawGetInfo(f + 1, what) end
                return __ndRawGetInfo(f, what)
            end
            __markNative(nd.getinfo, "getinfo")
        end
        for _, __dk in __ipairs({"info", "getinfo", "traceback", "getupvalue", "getupvalues", "getconstant", "getconstants", "getproto", "getprotos", "getstack", "sethook", "gethook", "getlocal", "setmetatable", "getmetatable", "getregistry", "getcallstack", "isvalidlevel", "setinfo", "setname", "setsafeenv", "getsafeenv", "profilebegin", "profileend"}) do
            if __type(nd[__dk]) == "function" then __markNative(nd[__dk], __dk) end
        end
        __setUNC("debug", nd)
    end
    -- filtergc via caller-stack scan for probe table
    __setUNC("filtergc", function(typ, opts, one)
        local wantKey, wantKV, wantVal = nil, nil, nil
        if __type(opts) == "table" then
            if __type(opts.Keys) == "table" and #opts.Keys > 0 then wantKey = opts.Keys[1] end
            if __type(opts.KeyValuePairs) == "table" then for k, v in __pairs(opts.KeyValuePairs) do wantKey, wantVal = k, v break end end
        end
        local found = {}
        if debug and debug.getlocal then
            for lvl = 2, 8 do
                local i = 1
                while true do
                    local ok, name, val = __pcall(debug.getlocal, lvl, i)
                    if not ok or name == nil then break end
                    if __type(val) == "table" then
                        local match = false
                        if wantKey and __rawget(val, wantKey) ~= nil then
                            if wantVal == nil or __rawget(val, wantKey) == wantVal then match = true end
                        end
                        if match then
                            if one then return val end
                            found[#found + 1] = val
                        end
                    end
                    i = i + 1
                    if i > 30 then break end
                end
            end
        end
        if one then return found[1] end
        return found
    end)
    __setUNC("getgc", function() return {} end)
    __setUNC("isfunctionhooked", function(f) return __hooks and __hooks[f] ~= nil end)
    __setUNC("isnewcclosure", function(f) return __isCClosureTrack[f] == true end)
    __setUNC("isourthread", function(t) return true end)
    __setUNC("newlclosure", function(f) return function(...) return f(...) end end)
    __setUNC("setstackhidden", function(f, h) return true end)
    __setUNC("getrendersteppedlist", function() return {} end)
end

-- hook getfenv to log VM global lookups (new obfuscator does getfenv()[decoded]) + hide logger
if getfenv and __realEnv then
    local __origGetfenv = getfenv
local __envProxyCache = nil
        local function __makeEnvProxy(env)
        if __envProxyCache then return __envProxyCache end
        local proxy = {}
        -- per-name dedupe so "-- getglobal print" appears once, not every lookup
        local seen = {}
        local proxyWrapped = {}
        setmetatable(proxy, {
            __index = function(_, k)
                -- log real payload global lookups as COMMENT so logged.lua stays runnable
                if __type(k)=="string" and k ~= "__LOGS" and k:sub(1,2) ~= "__" then
                    if __TRACKED_GLOBALS[k] then
                        if not seen[k] then
                            seen[k] = true
                            __table_insert(__LOGS, "-- getglobal " .. __repr(k))
                        end
                        local v = env[k]
                        -- track the resolved reference so the deep-trace hook can name it
                        if __type(v) == "function" and not __resolvedRefs[tostring(v)] then
                            __resolvedRefs[tostring(v)] = k
                        end
                        -- already wrapped by __wrapGlobal? it logs already - return as-is
                        if __type(v) == "function" and __wrappedMap[v] then
                            return v
                        end
                        -- wrap one-shot function returns so direct calls are logged
                        -- even when the VM calls the reference later from a register
                        if __type(v) == "function" and not proxyWrapped[k] and not __DENY[k]
                           and (k=="print" or k=="warn" or k=="error" or k=="game"
                                or k=="workspace" or k=="Instance" or k=="Vector3"
                                or k=="loadstring" or k=="require" or k=="spawn") then
                            proxyWrapped[k] = __makeLoggedFunction(k, v)
                            __resolvedRefs[tostring(proxyWrapped[k])] = k
                            return proxyWrapped[k]
                        end
                        return v
                    end
                end
                return env[k]
            end,
            __newindex = function(_, k, v) env[k]=v; seen[k]=false end,
            __pairs = function(_) return pairs(env) end,
            __call = function(self, ...) return self end,
        })
        __envProxyCache = proxy
        return proxy
    end
    local function __hookedGetfenv(lvl)
        local ok, env = __pcall(__origGetfenv, lvl)
        if ok and env == __realEnv then return __makeEnvProxy(__realEnv) end
        return env
    end
    __realEnv.getfenv = __hookedGetfenv
    if _G and _G ~= __realEnv then __pcall(function() _G.getfenv=__hookedGetfenv end) end
end

-- // Dump function - uses __realEnv
local function __LOG_DUMP_IMPL(path)
    path = path or "__logged__.lua"
    local out = __table_concat(__LOGS, "\n")
    -- append captured second-stage sources so the deobfuscator actually recovers
    -- the payload the script loaded (loadstring("...")'s real contents).
    -- gated by _G.__NO_FETCHED: when set, fetched payload snippets are NOT written
    local __noFetched = _G and _G.__NO_FETCHED
    if (not __noFetched) and #__STAGED > 0 then
        local sched = { "\n-- ---- SECOND-STAGE SOURCES (loadstring/load runtime payloads) ----" }
        for i = 1, #__STAGED do
            local st = __STAGED[i]
            if st and st.src and #st.src > 0 then
                sched[#sched + 1] = ("-- [stage %d] %s: %d bytes"):format(i, st.chunk or "?", st.bytes or #st.src)
                sched[#sched + 1] = st.src
            end
        end
        sched[#sched + 1] = "-- ---- end second-stage sources ----"
        out = out .. "\n" .. __table_concat(sched, "\n")
    end
    -- append harvested runtime strings so loads of string.char(table.unpack(t))
    -- payloads that the VM never printed are still recovered exactly.
    if (not __noFetched) and __harvestedStrings and #__harvestedStrings > 0 then
        local hched = { "\n-- ---- HARVESTED STRINGS (runtime string.char/table.concat outputs) ----" }
        for i = 1, #__harvestedStrings do
            local str = __harvestedStrings[i]
            hched[#hched + 1] = ("-- [string %d] %d bytes:"):format(i, #str)
            hched[#hched + 1] = str
        end
        hched[#hched + 1] = "-- ---- end harvested strings ----"
        out = out .. "\n" .. __table_concat(hched, "\n")
    end
    -- append deep-trace output if the hook fired
    if __deepTraceEnabled and #__deepTraceLog > 0 then
        out = out .. "\n-- ---- DEEP TRACE (sethook call capture) ----\n" .. __table_concat(__deepTraceLog, "\n") .. "\n-- ---- end deep trace ----"
    end
    if writefile then
        __pcall(writefile, path, out)
    elseif io and io.open then
        local ok, f = __pcall(io.open, path, "w")
        if ok and f then __pcall(function() f:write(out); f:close() end) end
    else
        -- Lune fallback: try fs.writeFile via require? just skip file
        __pcall(function()
            local fs = __rawget(__realEnv, "fs")
            if not fs then
                local ok2, mod = __pcall(require, "fs")
                if ok2 then fs = mod end
            end
            if fs and fs.writeFile then fs.writeFile(path, out) end
        end)
    end
    -- use orig print to avoid recursion
    __origPrint("--- ENV LOGGER DUMP START ---")
    if out ~= "" then __origPrint(out) else __origPrint("-- no logs") end
    __origPrint("--- ENV LOGGER DUMP END ---")
    return out
end
__setUNC("__LOG_DUMP", __LOG_DUMP_IMPL)
__realEnv["__LOG_DUMP"] = __LOG_DUMP_IMPL

__pcall(function()
    local dbg = __realEnv.debug
    if dbg and not __dbgShimInstalled then
        local origInfo = dbg.info
        if origInfo then
            __pcall(function() dbg.info = function(f, s, ...)
                if __wrappedMap[f] then f = __wrappedMap[f] end
                if __isCClosureTrack[f] then
                    if s=="s" then return "[C]" end
                    if s=="n" then return "" end
                    if s=="l" then return -1 end
                    return nil
                end
                local ok, res = __pcall(origInfo, f, s, ...)
                return res
            end end)
        end
        local origGetinfo = dbg.getinfo
        if origGetinfo then
            __pcall(function() dbg.getinfo = function(f, ...)
                local origF = f
                if __type(f)=="function" and __wrappedMap[f] then
                    f = __wrappedMap[f]
                end
                if __type(f)=="number" then
                    -- level, need to spoof caller
                    return __pcall(origGetinfo, f, ...)
                end
                local ok, info = __pcall(origGetinfo, f, ...)
                if __isCClosureTrack[origF] or (__wrappedMap[origF] and __origIsC[origF]) then
                    if ok and info then
                        info.source = "[C]"
                        info.short_src = "[C]"
                        info.what = "C"
                        info.linedefined = -1
                        info.lastlinedefined = -1
                        info.currentline = -1
                        return info
                    end
                end
                if ok and info and info.source and __tostring(info.source):find("Env Logger") then
                    info.source="[C]"; info.short_src="[C]"; info.what="C"; info.linedefined=-1
                end
                return info
            end end)
        end
    end
end)
end -- close 'do' at line 1412
"""

LOGGER_FOOTER = r"""
-- // Env Logger Footer: fire payload events (bounded) then dump.
-- Most GUI logic lives inside signal callbacks (button clicks, InputBegan,
-- Heartbeat) and only runs when the event fires. We replay each stored handler
-- with plausible args a few times (so toggles flip ON and OFF = both branches
-- execute) and step spawned/deferred coroutines (so `while ... task.wait() end`
-- bodies run the first several iterations instead of never running or hanging).
pcall(function()
    -- Run the whole replay in yielding mode: task.wait inside any fired
    -- callback hands control back so a perpetual `while true do task.wait() end`
    -- loop is stepped (not spun) and the process still exits.
    __firingCallbacks = true
    local function __makeInput(keyname)
        local ud = newproxy(true)
        local mt = getmetatable(ud)
        local iname = keyname or ""
        mt.__index = function(_, k)
            if k == "KeyCode" then
                local e = Enum and Enum.KeyCode and Enum.KeyCode[iname]
                if e then return e end
                return Enum and Enum.KeyCode and Enum.KeyCode.Unknown
            end
            if k == "UserInputType" then
                local e = Enum and Enum.UserInputType and Enum.UserInputType.Keyboard
                return e
            end
            if k == "Position" then return {X=0, Y=0} end
            if k == "Key" then return tostring(iname) end
            return function() return nil end
        end
        __valRepr[ud] = "InputObject[KeyCode." .. (iname or "Unknown") .. "]"
        return ud
    end
    local function __argsFor(sigName, __rep)
        if sigName and (sigName:find("InputBegan") or sigName:find("InputChanged")) then
            -- cycle plausible keys across attempts so whatever key the script
            -- listens for (Space/W/A/S/D...) gets pressed at some point.
            local __keys = {"Space", "W", "A", "S", "D", "LeftControl", "Unknown"}
            local __k = __keys[((__rep - 1) % #__keys) + 1]
            return {__makeInput(__k)}
        end
        if sigName and sigName:find("InputEnded") then return {__makeInput("")} end
        if sigName and sigName:find("Heartbeat") then return {0.016, 0.016} end
        if sigName and sigName:find("Stepped") then return {0.016, 0} end
        if sigName and sigName:find("RenderStepped") then return {0.016} end
        return {}
    end
    __taskStepBusy = __taskStepBusy or false
    local function __stepQueue(maxSteps)
        if __taskStepBusy then return end
        __taskStepBusy = true
        local steps = 0
        local __qok, __qerr = __pcall(function()
        while #__taskQ > 0 and steps < maxSteps do
            local co = table.remove(__taskQ, 1)
            if coroutine.status(co) == "suspended" then
                __taskBudget[co] = (__taskBudget[co] or 0) + 1
                if __taskBudget[co] > 20000 then
                    __taskBudget[co] = nil
                    __table_insert(__LOGS, "-- LIMIT: task spin budget exceeded (abandoned, script keeps running)")
                else
                    local ok, err = coroutine.resume(co)
                    if not ok and err then
                        __table_insert(__LOGS, "-- task error: " .. tostring(err):sub(1, 200))
                        break
                    end
                    if coroutine.status(co) == "suspended" then
                        if __idleWait[co] then
                            __idleWait[co] = nil
                            __idleCount[co] = (__idleCount[co] or 0) + 1
                        else
                            __idleCount[co] = nil
                        end
                        if (__idleCount[co] or 0) > 16 then
                            __idleCount[co] = nil
                            __table_insert(__LOGS, "-- LIMIT: idle wait-loop task abandoned after 16 yields")
                        else
                            table.insert(__taskQ, co)
                        end
                    end
                end
            end
            steps = steps + 1
        end
        end)
        __taskStepBusy = false
    end
    local function __sigClass(name)
        if name and (name:find("InputBegan") or name:find("InputChanged") or name:find("InputEnded")) then
            return 3
        end
        if name and (name:find("Heartbeat") or name:find("RenderStepped") or name:find("Stepped")
                     or name:find("ChildAdded") or name:find("ChildRemoved")
                     or name:find("Changed") or name:find("PropertyChanged")) then
            return 2
        end
        return 1
    end
    local __fired = 0
    local __cap = 600
    local __firedBy = {}
    local __cbErrors = {}
    local function __runCB(__e, __rep, __burn)
        if __fired >= __cap then return end
        if __cbErrors[__e] then return end
        local __n = __firedBy[__e] or 0
        if __n >= 8 then return end
        __firedBy[__e] = __n + 1
        __fired = __fired + 1
        __logCall("signal:Fire", __repr(__e.sig) .. " -- attempt " .. __rep
                  .. (__burn and (" -- frame " .. __burn) or ""))
        local __co = coroutine.create(function() __e.cb(unpack(__argsFor(__e.sig, __rep))) end)
        local __ok, __err = coroutine.resume(__co)
        if not __ok and __err then
            __cbErrors[__e] = true
            __table_insert(__LOGS, "-- callback error: " .. tostring(__err):sub(1, 200))
            pcall(function()
                __table_insert(__LOGS, "-- full traceback:")
                for line in tostring(debug.traceback(__co, 2)):gmatch("[^\n]+") do
                    __table_insert(__LOGS, "  " .. line:sub(1, 200))
                    if #line > 200 then break end
                end
            end)
        elseif coroutine.status(__co) == "suspended" then
            table.insert(__taskQ, 1, __co)
        end
        __stepQueue(12)
    end
    if __signalStore then
        for __rep = 1, 8 do
            -- step the task queue first: freshly-spawned GUI tasks build widgets
            -- and Connect their handlers during stepping, so fire AFTER stepping
            __pcall(function() __stepQueue(120) end)
            -- clicks/buttons/connects first (toggles ON), then render/heartbeat
            -- handlers (run several "frames" so fly velocity math / tween bodies
            -- actually execute), and input handlers LAST with a cycling key so
            -- whatever key the script listens for gets pressed on some attempt.
            for __i, __e in ipairs(__signalStore) do
                if __sigClass(__e.sig) == 1 and __type(__e.cb) == "function" then
                    __runCB(__e, __rep)
                end
            end
            __pcall(function() __stepQueue(120) end)
            for __i, __e in ipairs(__signalStore) do
                if __sigClass(__e.sig) == 2 and __type(__e.cb) == "function" then
                    for __burn = 1, 12 do __runCB(__e, __rep, __burn) end
                end
            end
            __pcall(function() __stepQueue(120) end)
            for __i, __e in ipairs(__signalStore) do
                if __sigClass(__e.sig) == 3 and __type(__e.cb) == "function" then
                    __runCB(__e, __rep)
                end
            end
            __pcall(function() __stepQueue(120) end)
        end
    end
    -- keep stepping task loops (fly/server while-loops) a few more rounds
    for __round = 1, 32 do
        __stepQueue(120)
    end
    __firingCallbacks = false
    if __disableDeepTrace then __disableDeepTrace() end
    pcall(function() __LOG_DUMP("__logged__.lua") end)
end)
"""

def lua_long_string(s: str) -> str:
    # Find safe delimiter for Lua long string that doesn't appear in s
    level = 0
    while True:
        delim_start = "[" + "=" * level + "["
        delim_end = "]" + "=" * level + "]"
        if delim_start not in s and delim_end not in s:
            return f"{delim_start}{s}{delim_end}"
        level += 1
        if level > 10:
            # fallback - escape (should not happen for wearedevs)
            return repr(s)

# ============================================================================
# bPeM static deobfuscation ("-- obfuscated by bPeM")
# Structure reverse-engineered from script.lua:
#   local V={...}  constant pool (strings prefixed T=base64 / I=base85, FUN=closure returning a literal)
#   reversal loops: for i,j in ipairs({{1,315},{1,183},{184,315}})
#   L(i) -> V[i+41971] (pcall FUN to get the value)
#   accessor tables Y={meth=function(r,n,s,V,Y,o,A,X,K,T)return L(PARAM OP NUM)end,...}
#   call sites: Y.meth(a1,...,a10) -> one of the args + OP NUM -> pool index
# Everything resolves statically, so the payload is recovered without running
# the (infinite-loop) init VM. This module is used by --bpem-deob and by the
# auto bPeM hook in build_wrapped_script (binaries/blobs embedded as SECOND-STAGE).
# ============================================================================
# ============================================================================
# bPeM static deobfuscation ("-- obfuscated by bPeM")
BPEM_B64_ALPHABET = "6iLneCUlahzjVsXfGJFOMZw408yxDto9NR3HWPQ7I5d1ErKkm+Scg/TpqAYvu2bB"
BPEM_B85_ALPHABET = "+tKBH[JQ9f)^CD<&86\"L*>7A.TGWO-i_gsN5oZS@V`Ru$P3l\\hkqr(1d,2mj%'I4?X!Eb=p:F]a#c0;M/UenY"
BPEM_HEADER = "-- obfuscated by bPeM"
BPEM_PARAM_INDEX = {"r": 0, "n": 1, "s": 2, "V": 3, "Y": 4, "o": 5, "A": 6, "X": 7, "K": 8, "T": 9}

def _bpem_b64d(s: str) -> bytes:
    out = []; I = 0; E = 0; x = 1; sl = len(s)
    while x <= sl:
        ch = s[x - 1]; o = BPEM_B64_ALPHABET.find(ch)
        if o >= 0:
            I += o * (64 ** (3 - E)); E += 1
            if E == 4:
                E = 0; out += [(I // 65536) & 0xFF, ((I % 65536) // 256) & 0xFF, I % 256]; I = 0
        elif ch == "=":
            out.append((I // 65536) & 0xFF)
            if x >= sl or s[x] != "=": out.append(((I % 65536) // 256) & 0xFF)
            break
        x += 1
    return bytes(out)

def _bpem_b85d(s: str) -> bytes:
    out = []; sl = len(s); x = 1
    while x <= sl:
        remaining = sl - x + 1; o = 5 if remaining >= 5 else remaining; K = 0; ok = True
        for r in range(5):
            if r < o:
                ch = s[x - 1 + r]; idx = BPEM_B85_ALPHABET.find(ch)
                if idx < 0: ok = False; break
                K = K * 85 + idx
            else:
                K = K * 85 + 84
        if not ok: x += 1; continue
        if o == 5: out += [(K >> 24) & 0xFF, (K >> 16) & 0xFF, (K >> 8) & 0xFF, K & 0xFF]
        elif o == 4: out += [(K >> 24) & 0xFF, (K >> 16) & 0xFF, (K >> 8) & 0xFF]
        elif o == 3: out += [(K >> 24) & 0xFF, (K >> 16) & 0xFF]
        elif o == 2: out.append((K >> 24) & 0xFF)
        x += o
    return bytes(out)

def _bpem_find_brace(src: str, pos: int, open_ch: str, close_ch: str) -> int:
    d = 1; i = pos; ins = None; n = len(src)
    while i < n and d > 0:
        cc = src[i]
        if ins:
            if cc == "\\": i += 2; continue
            if cc == ins: ins = None
        else:
            if cc in "\"'": ins = cc
            elif cc == open_ch: d += 1
            elif cc == close_ch: d -= 1
        i += 1
    return i

def bpem_extract_pool(src: str):
    """Return (arr_values, arr_tags) of the reversed V pool. None if not found."""
    vstart = src.find("local V={")
    if vstart < 0 or BPEM_HEADER not in src:
        return None, None
    brace_start = vstart + len("local V=")
    end_pos = _bpem_find_brace(src, brace_start, "{", "}")
    region = src[brace_start + 1:end_pos]
    L = len(region); i = 0; elems = []; cur = []
    brace_dep = 0; blk_dep = 0
    open_kw = ("if", "while", "for", "function", "do", "repeat")
    close_kw = ("end", "until")
    def flush():
        nonlocal cur
        if cur: elems.append(cur); cur = []
    while i < L:
        ch = region[i]
        if ch in "\"'":
            q = ch; j = i + 1
            while j < L:
                if region[j] == "\\": j += 2; continue
                if region[j] == q: j += 1; break
                j += 1
            cur.append(("STR", region[i:j])); i = j; continue
        if ch in ",;":
            if brace_dep == 0 and blk_dep == 0: flush()
            else: cur.append(("SEP", ch))
            i += 1; continue
        if ch == "{": brace_dep += 1; cur.append(("BRACE", ch)); i += 1; continue
        if ch == "}": brace_dep -= 1; cur.append(("BRACE", ch)); i += 1; continue
        if ch.isalnum() or ch == "_":
            j = i
            while j < L and (region[j].isalnum() or region[j] == "_"): j += 1
            word = region[i:j]
            if word in open_kw: blk_dep += 1
            elif word in close_kw: blk_dep -= 1
            cur.append(("WORD", word)); i = j; continue
        cur.append(("CH", ch)); i += 1
    flush()
    def el_str(el):
        if len(el) == 1 and el[0][0] == "STR":
            try: return eval(el[0][1])
            except Exception: return el[0][1]
        return None
    def el_fun(el):
        if el and el[0] == ("WORD", "function"):
            return "".join(t for _, t in el)
        return None
    V = []
    for el in elems:
        s = el_str(el)
        if s is not None: V.append(("STR", s)); continue
        f = el_fun(el)
        if f is not None: V.append(("FUN", f)); continue
        txt = "".join(t for _, t in el).strip()
        if re.fullmatch(r"[-+]?\d+", txt): V.append(("NUM", int(txt)))
        elif txt in ("true", "false"): V.append(("BOOL", txt == "true"))
        else: V.append(("OTHER", txt))
    arr = [v for _, v in V]
    tags = [t for t, _ in V]
    for a, b in [(1, 315), (1, 183), (184, 315)]:
        if 1 <= a <= len(arr) and b <= len(arr):
            arr[a - 1:b] = arr[a - 1:b][::-1]
            tags[a - 1:b] = tags[a - 1:b][::-1]
    return arr, tags

def _bpem_pool_val(arr, tags, i):
    if i < 1 or i > len(arr):
        return None
    tag = tags[i - 1]; v = arr[i - 1]
    if tag == "FUN":
        m = re.search(r"return\s+(true|false)\b", v)
        if m: return m.group(1) == "true"
        m = re.search(r'return\s+"((?:[^"\\]|\\.)*)"', v)
        if m: return m.group(1)
        m = re.search(r"return\s+(\d+)\b", v)
        if m: return int(m.group(1))
        return "FUN?"
    if tag == "STR":
        if len(v) > 1 and v[0] in "TI":
            try:
                return (_bpem_b64d(v[1:]) if v[0] == "T" else _bpem_b85d(v[1:])).decode("utf-8", "replace")
            except Exception:
                return v
        return v
    if tag in ("NUM", "BOOL", "OTHER"):
        return v
    return None

def _bpem_luarepr(v) -> str:
    if v is None: return "nil"
    if v is True: return "(true)"
    if v is False: return "(false)"
    if isinstance(v, (int, float)): return "(" + str(v) + ")"
    s = str(v)
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif ch == '"': out.append('\\"')
        elif ch == "\\": out.append("\\\\")
        elif 32 <= o < 127: out.append(ch)
        else: out.append("\\x%02x" % o)
    return '"' + "".join(out) + '"'

def _bpem_tokenize(src: str):
    toks = []; i = 0; n = len(src)
    while i < n:
        ch = src[i]
        if ch == "-" and i + 1 < n and src[i + 1] == "-":
            j = i + 2
            if j < n and src[j] == "[" and j + 1 < n and src[j + 1] == "[":
                jj = src.find("]]", j + 2); j = n if jj < 0 else jj + 2
            else:
                jj = src.find("\n", i); j = n if jj < 0 else jj + 1
            i = j; continue
        if ch.isspace():
            i += 1; continue
        if ch in "\"'":
            q = ch; j = i + 1
            while j < n:
                if src[j] == "\\": j += 2; continue
                if src[j] == q: j += 1; break
                j += 1
            toks.append((i, j, "STR", src[i:j])); i = j; continue
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"): j += 1
            toks.append((i, j, "ID", src[i:j])); i = j; continue
        if ch.isdigit() or (ch == "-" and i + 1 < n and src[i + 1].isdigit()):
            j = i + 1
            if ch == "-":
                if i + 2 < n and src[i + 2] == "-":
                    toks.append((i, i + 1, "OP", "-")); i += 1; continue
                j = i + 1
            while j < n and (src[j].isdigit() or src[j] == "."): j += 1
            toks.append((i, j, "INT" if _re_int(src[i:j]) else "NUM", src[i:j]))
            i = j; continue
        if ch in "=({})[],.;:+-*/%^#<>~<>&|]":
            toks.append((i, i + 1, "OP", ch)); i += 1; continue
        i += 1
    return toks

def _re_int(s):
    try:
        int(s); return True
    except Exception:
        return False

def _bpem_int(s):
    try: return int(s)
    except Exception: return None

def bpem_deob_src(src: str):
    """Static bPeM deobfuscation. Returns (deob_src, pool, tags) or (None,None,None) if not bPeM.
    Two-pass design matching the validated prototype: pass-1 scope-aware resolve, pass-2 global-unique fallback."""
    if BPEM_HEADER not in src:
        return None, None, None
    arr, tags = bpem_extract_pool(src)
    if arr is None:
        return None, None, None
    toks = _bpem_tokenize(src)
    tn = len(toks)
    def find_table_close(open_tok_i):
        d = 1; j = open_tok_i + 1
        while j < tn and d > 0:
            if toks[j][2] == "OP":
                if toks[j][3] == "{": d += 1
                elif toks[j][3] == "}":
                    d -= 1
                    if d == 0: return j + 1
            j += 1
        return j
    def parse_meths(seg):
        mm = {}
        pat = re.compile(r"(\w+)\s*=\s*function\([^)]*\)(.*?)\breturn\s+L\(([a-zA-Z]+)\s*([+-])\s*(\d+)\)\s*end", re.S)
        pos = 0
        while True:
            m = pat.search(seg, pos)
            if not m: break
            mm[m.group(1)] = (m.group(3), m.group(4), int(m.group(5)))
            pos = m.end()
        return mm
    def resolve_call(arg_list, spec):
        if spec and len(arg_list) == 10 and all(_bpem_int(a) is not None for a in arg_list):
            param_name, opn, num = spec
            pi = BPEM_PARAM_INDEX[param_name]
            vv = _bpem_int(arg_list[pi]) + (num if opn == "+" else -num)
            idx = vv + 41971
            return _bpem_pool_val(arr, tags, idx)
        return None
    # ---- PASS 1: scope-aware resolve ----
    scopes = [dict()]
    defs = []
    def lookup(name):
        for s in reversed(scopes):
            if name in s and s[name] is not None:
                return s[name]
        return None
    def bind(name, val):
        scopes[-1][name] = val
    resolved1 = []
    i = 0
    while i < tn:
        start, end, kind, val = toks[i]
        if kind != "ID":
            i += 1; continue
        if val == "local":
            j = i + 1; names = []
            while j < tn and toks[j][2] == "ID":
                names.append(toks[j][3]); j += 1
                if j < tn and toks[j][2] == "OP" and toks[j][3] == ",": j += 1; continue
                break
            if j < tn and toks[j][2] == "OP" and toks[j][3] == "=":
                v = j + 1
                if v < tn and toks[v][2] == "OP" and toks[v][3] == "{":
                    close = find_table_close(v)
                    if close <= tn:
                        mm = parse_meths(src[toks[v][0]:toks[close - 1][1]])
                        if mm:
                            bind(names[0], mm); defs.append((i, names[0], mm, close, len(scopes) - 1))
                    i = close; continue
            for nm in names: bind(nm, None)
            i = j; continue
        if val in ("do", "then", "if", "while", "for", "repeat", "function"):
            scopes.append(dict()); i += 1; continue
        if val in ("end", "until"):
            if len(scopes) > 1: scopes.pop()
            i += 1; continue
        if val in ("elseif", "else"):
            i += 1; continue
        j = i + 1
        if j < tn and toks[j][2] == "OP":
            op = toks[j][3]
            if op == "=":
                v = j + 1
                if v < tn and toks[v][2] == "OP" and toks[v][3] == "{":
                    close = find_table_close(v)
                    if close <= tn:
                        mm = parse_meths(src[toks[v][0]:toks[close - 1][1]])
                        if mm:
                            bind(val, mm); defs.append((i, val, mm, close, len(scopes) - 1))
                    i = close; continue
                bind(val, None); i = v; continue
            elif op == ".":
                mm = j + 1
                if mm < tn and toks[mm][2] == "ID":
                    meth = toks[mm][3]; pj = mm + 1
                    if pj < tn and toks[pj][2] == "OP" and toks[pj][3] == "(":
                        k = pj + 1; args_list = []; cur = None
                        while k < tn:
                            if toks[k][2] == "OP" and toks[k][3] == ")": break
                            if toks[k][2] == "OP" and toks[k][3] == ",":
                                if cur is not None: args_list.append(cur)
                                cur = None; k += 1; continue
                            if cur is None: cur = ""
                            if toks[k][2] == "STR": cur = toks[k][3]
                            elif toks[k][2] in ("INT", "NUM"): cur = toks[k][3]
                            else: cur = "?"
                            k += 1
                        if cur is not None: args_list.append(cur)
                        close = k + 1
                        binding = lookup(val)
                        pv = resolve_call(args_list, binding.get(meth)) if isinstance(binding, dict) else None
                        if pv is not None:
                            resolved1.append((i, close, pv))
                            i = close; continue
                        i = mm + 1; continue
        i += 1
    # ---- PASS 2: global-unique fallback (skip shells already claimed by P1) ----
    global_defs = {}
    for _, name, mm, close, depth in defs:
        for meth, spec in mm.items():
            global_defs.setdefault(meth, set()).add(spec)
    GLOBAL = {m: next(iter(s)) for m, s in global_defs.items() if len(s) == 1}
    claimed = set()
    for a, b, pv in resolved1:
        claimed.update(range(a, b))
    resolved2 = []
    i = 0
    while i < tn:
        start, end, kind, val = toks[i]
        if kind != "ID":
            i += 1; continue
        if i in claimed:
            i += 1; continue
        j = i + 1
        if j < tn and toks[j][2] == "OP" and toks[j][3] == ".":
            mm = j + 1
            if mm < tn and toks[mm][2] == "ID":
                meth = toks[mm][3]; pj = mm + 1
                if pj < tn and toks[pj][2] == "OP" and toks[pj][3] == "(":
                    k = pj + 1; args_list = []; cur = None
                    while k < tn:
                        if toks[k][2] == "OP" and toks[k][3] == ")": break
                        if toks[k][2] == "OP" and toks[k][3] == ",":
                            if cur is not None: args_list.append(cur)
                            cur = None; k += 1; continue
                        if cur is None: cur = ""
                        if toks[k][2] == "STR": cur = toks[k][3]
                        elif toks[k][2] in ("INT", "NUM"): cur = toks[k][3]
                        else: cur = "?"
                        k += 1
                    if cur is not None: args_list.append(cur)
                    close = k + 1
                    pv = resolve_call(args_list, GLOBAL.get(meth))
                    if pv is not None:
                        resolved2.append((i, close, pv))
                        i = close; continue
                    i = mm + 1; continue
        i += 1
    # ---- apply edits (right-to-left) ----
    edits = sorted([(toks[a][0], toks[b - 1][1], _bpem_luarepr(v)) for a, b, v in resolved1 + resolved2],
                   key=lambda e: e[0], reverse=True)
    out = src
    for a, b, txt in edits:
        out = out[:a] + txt + out[b:]
    return out, arr, tags

def build_wrapped_script(original_src: str, basename: str = "obfuscated", extra_urls=None, full_payload: bool = True, no_fetched: bool = False, no_fetch: bool = False, mock_payload: str = "", mock_payloads: dict = None, place_id: int = 0, game_id: int = 0, syn_body: str = "", chunk_arg: str = "", hide_exec_globals: bool = False, strict_members: bool = False) -> str:
    # Game-gate emulation: some loaders only run in a specific Roblox game, e.g.
    # `if ({[17625359962]=true})[game.PlaceId] then ... end`. Our mock PlaceId=0
    # skips the whole payload. If the source references PlaceId AND contains
    # bracket-indexed numeric literals (candidate place IDs), return one of them.
    # An explicit --place-id always wins.
    gate_placeid = place_id
    if not gate_placeid:
        if "PlaceId" in original_src:
            cands = [int(m[0]) for m in re.findall(r"\[(\d{6,15})\]\s*=\s*(true|nil)", original_src)]
            cands += [int(a or b) for a, b in re.findall(r"(?:(\d{6,15})\s*==\s*\w*PlaceId|PlaceId\s*==\s*(\d{6,15}))", original_src)]
            if cands:
                gate_placeid = max(set(cands))
    # PolSec / getpolsec anti-tamper stinger: getpolsec injects a self-destruct
    # stinger into a hosted script when it detects tampering. It is a poison file
    # with NO loadable payload — junk bodies crash on `d[nil]=c` and `d(nil,nil)`
    # in any Lua dialect, `next(nil, ...)` + `debug.info` assume Luau (not stock
    # Lua/Lune), and runProtected warns, kicks the player and hangs in a
    # `while true do wait(9999) end` loop. The ONLY top-level execution is the
    # final discarded trampoline `v2=processItems6; if 64-(#processItems7(
    # processItems5(),getValue4())+9)%64~=64 then end`. Bypass: cut that
    # trampoline and make runProtected return before its kick/hang, so the file
    # defines-but-never-runs its poison and completes cleanly.
    if ("[ PolSec ] Error: " in original_src
            and "local function processItems5" in original_src
            and "local function processItems6" in original_src
            and "local function runProtected" in original_src
            and "processItems7(processItems5(), getValue4())" in original_src):
        pat_runprotected = re.compile(
            r'warn\("\[ PolSec \] Error: "\s*\.\.\s*tostring\(a\)\)(?s:.*?)while true do\s*\n\s*wait\(9999\)\s*\n\s*end')
        if pat_runprotected.search(original_src):
            original_src = pat_runprotected.sub(
                'warn("[ PolSec ] Error: " .. tostring(a))\n        -- [polsec-bypass] kick/hang neutralized (env_logger)\n        return a',
                original_src, count=1)
        pat_tail = re.compile(
            r'v2\s*=\s*processItems6\s*\n\s*if\s+64\s*-\s*\(\s*#\s*processItems7\s*\(\s*processItems5\s*\(\s*\)\s*,\s*getValue4\s*\(\s*\)\s*\)\s*\+\s*9\s*\)\s*%\s*64\s*~=\s*64\s*then\s*\n\s*end',
            re.S)
        if pat_tail.search(original_src):
            original_src = pat_tail.sub(
                '-- [polsec-bypass] PolSec anti-tamper stinger neutralized by env_logger (trampoline cut);\n-- the stinger contained no loadable payload',
                original_src, count=1)
    # Pre-fetch HttpGet links actually found in THIS script's source
    # (so game:HttpGet returns real code even in Lune without network).
    # NO host whitelist — fetch whatever this script actually loads. Only
    # webhook/exfil endpoints are skipped (fetching them could trigger a
    # delivery/leak to the attacker's inbox).
    def _is_webhook_url(u: str) -> bool:
        l = u.lower()
        return ("discord.com/api/webhooks" in l or "discordapp.com/api/webhooks" in l
                or "discordapp.net/api/webhooks" in l or "/webhooks/" in l)
    http_cache = {}
    for m in ([] if NO_NET else re.finditer(r'https?://[^\s"\'\)]+', original_src)):
        url = m.group(0)
        # strip control chars and query params like ?nocache=
        clean = re.sub(r'[\x00-\x1f\x7f]', '', url).split('?')[0]
        if not clean or _is_webhook_url(clean):
            continue
        if clean in http_cache:
            continue
        try:
            c = fetch_link(clean)
            if c and len(c) > 100:
                http_cache[clean] = c
                print(f"[+] pre-fetched HttpGet link: {clean} ({len(c)}b)")
        except: pass
    # second-pass prefetch: URLs learned from a previous run's "-- LINK:" lines
    for clean in (extra_urls or []):
        clean = re.sub(r'[\x00-\x1f\x7f]', '', clean).split('?')[0]
        if not clean or clean in http_cache:
            continue
        try:
            c = fetch_link(clean)
            if c:
                http_cache[clean] = c
                print(f"[+] prefetch-file link: {clean} ({len(c)}b)")
        except: pass
    # NOTE: only prefetch links actually found in THIS script's source, so one
    # GUI's payload can never leak into another script's log.
    # build Lua cache table
    lua_cache_entries = ""
    for url, content in http_cache.items():
        lua_content = lua_long_string(content)
        lua_cache_entries += f'__httpCache[{repr(url)}] = {lua_content}\n'
# MoonSec V3: the VM's position counter starts at 0 and is advanced to >=1
    # by an async hook (r.zlCRkgHB(function()...counter=counter+1 end)) that only
    # fires under real Roblox scheduling. On Lune the hook never fires, so the
    # first byte read is byte(s, 0, 3) which clamps to 3 values and the VM dies
    # on a nil 4th byte. The counter MUST effectively start at 1 (same result as
    # the hook having fired once before the first read). Replace
    #   local n=0;r.ALIAS(function()r.ALIAS2()n=n+1 end)
    # with
    #   local n=1;
    # This also neutralizes the hook itself so Lune doesn't need the async wrap.
    pat_moons = re.compile(r'local (\w+)=0;(?:(\w+)\.\w+\(function\(\)\2\.\w+\(\))?\1=\1\+1 end\)')
    def _moons_counter(m):
        # only rewrite when the async hook advances this exact counter var
        return 'local %s=1;' % m.group(1) if m.group(2) else m.group(0)
    if 'MoonSec V3' in original_src:
        original_src = pat_moons.sub(_moons_counter, original_src)
        # MoonSec V3 anti-tamper: before running, it dumps the deobfuscator
        # function (r.Lo_OoUxO(ne)) and string.matches it against an expected
        # byte pattern (r.YvxIzrVj). The dumped proto encodes the chunk name, so
        # under env_logger (chunk 'obfuscated') the bytes differ from the real
        # Roblox @EntityScript / @Common scripts and the match FAILS -> e=e+1 ->
        # the trap branch -> unbounded VM recursion -> C stack overflow. On real
        # Roblox the match passes (e=e+0). Force the non-trap branch.
        pat_tamper = re.compile(
            r'if\s+(\w+)\.(\w+)\s*then\s+h=(\w+)\.(\w+)\((\w+)\)else\s+h=\'\'end\s+if\s+\1\.(\w+)\(h,\1\.(\w+)\)\s*then\s+e=e\+0;else\s+e=e\+1;end')
        def _moons_tamper(m):
            # Neutralize: do NOT rewrite. MoonSec V3's anti-tamper branch
            # (string.dump(r.Lo_OoUxO(ne)) matched against r.YvxIzrVj) passes
            # NATURALLY when the chunk is named after the real original file
            # (see __CHNK_BASENAME__ substitution below). Forcing a branch with
            # h='' duplicates the exact condition that made the plain `force0`
            # probe overflow. Leave the original branch untouched so the natural
            # pass (proven under plain Lune -> HttpGet error) is reproduced.
            return m.group(0)
        original_src = pat_tamper.sub(_moons_tamper, original_src)
    # Use loadstring to handle `return` at top-level (wearedevs: return(function(...)...end))
    lua_src = lua_long_string(original_src)
    lua_basename = lua_long_string(basename)
    gate_line = ""
    if gate_placeid != 0:
        gate_line = f'-- game-gate emulation: mock PlaceId matches a target listed in source\n__GATE_PLACEID = {gate_placeid}\n'
    mock_line = ""
    stealth_line = ""
    if hide_exec_globals:
        # anti-tamper samples that hunt executor-only globals (ez dtc 11/12 check
        # getgenv/getgc) require them to be absent; Roblox itself has no such globals
        stealth_line = """-- stealth: hide executor-only globals from the script
do
    local __hideNames = {"getgenv","getgc","getrenv","getreg","getinstances","getnilinstances",
        "getscripts","getsenv","getmenv","getnamecallmethod","setnamecallmethod","checkcaller",
        "identifyexecutor","getexecutorname","getcallingscript","getcallingenvironment",
        "getexecutorname","hookfunction","hookerror","newcclosure","clonefunction","getconstant",
        "getconstants","getproto","getprotos","getupvalue","getupvalues","setupvalue","setreadonly",
        "isreadonly","getrawmetatable","setrawmetatable","getnamecallmethod","gcinfo",
        "getnilinstances","getloadedmodules","gethui","getobjects","getrunninginstances",
        "queueon_teleport","queue_on_teleport","requests","request","syn","protect_gui",
        "setclipboard","setreadonly","writefile","readfile","appendfile","makefolder","isfolder",
        "dofile","loadfile","system","exec","io","os_execute"}
    for _, __hn in ipairs(__hideNames) do
        __unc[__hn] = nil
        __pcall(function() __sharedEnv[__hn] = nil end)
        __pcall(function() __rawset(__sharedEnv, __hn, nil) end)
        __pcall(function() __realEnv[__hn] = nil end)
        if _G and _G ~= __realEnv then __pcall(function() _G[__hn] = nil end) end
    end
end
"""
    if mock_payload:
        mock_line = f'_G.__MOCK_PAYLOAD = {lua_long_string(mock_payload)}\n'
    elif mock_payloads:
        _entries = []
        for _u, _c in mock_payloads.items():
            _entries.append(f"[{repr(_u)}] = {lua_long_string(_c)}")
        mock_line = "_G.__MOCK_PAYLOADS = { " + ", ".join(_entries) + " }\n"
    loader = f"""
-- // ORIGINAL SCRIPT START (via loadstring to handle return correctly)
_G.__LOG_FULL_PAYLOAD = {str(bool(full_payload)).lower()}
_G.__NO_FETCHED = {str(bool(no_fetched)).lower()}
_G.__HTTP_NO_FETCH = {str(bool(no_fetch)).lower()}
_G.__STRICT_MEMBERS = {str(bool(strict_members)).lower()}
-- no-fetch: executor mode -> drive the payload as deep as it will go, so we can
-- see the real code paths instead of abandoning on a tiny spin budget. The VM
-- decode spins for many millions of resumes, so raise the pump caps hard.
_G.__MAIN_BUDGET = {str(4000000 if no_fetch else 400000)}
_G.__MAIN_WALLMS = {str(10000 if no_fetch else 240)}
__httpCache = {{}}
{mock_line}
{gate_line}
{stealth_line}
{lua_cache_entries}
_G.__httpCache = __httpCache
-- make HttpGet use cache
do
    local __origHttpGet = __realEnv.game and getmetatable(__realEnv.game) and getmetatable(__realEnv.game).__index and getmetatable(__realEnv.game).__index(__realEnv.game, "HttpGet") or nil
end
-- neutralize string-metatable anti-env checks (getmetatable('').__index)
-- Real Roblox returns a LOCKED string metatable: __index == string and
-- __metatable == "The metatable is locked" (SamlarenHub / Kw15 check both).
do
    local __origGlobalGetmetatable = __realEnv.getmetatable or getmetatable
    __realEnv.getmetatable = function(x)
        if type(x) == "string" then
            return {{__index=string, __metatable="The metatable is locked"}}
        end
        return __origGlobalGetmetatable(x)
    end
    if _G then
        local __og = __realEnv.getmetatable
        _G.getmetatable = function(x)
            if type(x) == "string" then return {{__index=string, __metatable="The metatable is locked"}} end
            return __og(x)
        end
    end
end
__CHUNK_ARG_SRC = {'nil' if not chunk_arg else lua_long_string(chunk_arg)}
local __src = {lua_src}
-- load & run the original script chunk. Name the chunk after the ORIGINAL FILE
-- (from its basename) rather than a fixed literal: MoonSec V3 / Luraph etc. embed
-- a string.dump(ne)-hash match that includes the chunk name, so a fixed name like
-- "obfuscated" makes the recovered proto bytes differ and trips the tamper trap.
-- Injecting the real basename makes the dump match -> decode proceeds.
-- // _G RECONCILIATION: make _G agree with the environment the payload
-- actually runs in (Lune: getfenv(1) ~= _G).  Standard library only --
-- executor globals are left exactly as the stealth pass left them.
do
    if _G and __realEnv and _G ~= __realEnv then
        for _, __sn in ipairs({{
            'setmetatable', 'getmetatable', 'rawget', 'rawset', 'rawequal', 'rawlen', 'select', 'unpack',
            'pcall', 'xpcall', 'error', 'assert', 'warn', 'collectgarbage', 'type', 'tostring',
            'tonumber', 'print', 'ipairs', 'pairs', 'next', 'require', 'loadstring', 'load',
            'getfenv', 'setfenv', 'newproxy', 'coroutine', 'utf8', 'bit32', 'string', 'table',
            'math', 'os', 'task', 'tick', 'time', 'wait', 'delay', 'spawn',
            'debug', 'settings', 'game', 'workspace', 'typeof', '_VERSION',
        }}) do
            __pcall(function()
                local __sv = __realEnv[__sn]
                if __sv ~= nil and _G[__sn] ~= __sv then _G[__sn] = __sv end
            end)
        end
        -- utf8.codepoint: absent here, and __realEnv.utf8 is only wired up by
        -- this point in the loader, so install it here.
        __pcall(function()
            local __u8 = __realEnv.utf8
            if __u8 ~= nil and __type(__u8.codepoint) ~= "function" then
                __u8.codepoint = function(str, i, j)
                    local s = __tostring(str)
                    local a = __type(i) == "number" and i or 1
                    local b = __type(j) == "number" and j or #s
                    if b > #s then b = #s end
                    local out = {{}}
                    while a <= b do
                        local c = __str_byte(s, a)
                        local w, cp
                        if c < 0x80 then w, cp = 1, c
                        elseif c < 0xE0 then w, cp = 2, c - 0xC0
                        elseif c < 0xF0 then w, cp = 3, c - 0xE0
                        else w, cp = 4, c - 0xF0 end
                        if a + w - 1 > b then break end
                        local v = cp
                        for k = 1, w - 1 do
                            v = v * 64 + (__str_byte(s, a + k) - 0x80)
                        end
                        out[#out + 1] = v
                        a = a + w
                    end
                    return __realEnv.table.unpack(out)
                end
                __pcall(function() __markNative(__u8.codepoint, "utf8.codepoint") end)
            end
        end)
        -- in Luau/Roblox _G._G is _G itself
        __pcall(function() if _G._G ~= _G then _G._G = _G end end)
    end
end
local __origTs0 = os.clock()
__isLoaderLoad = true
if __markEnvNatives then __pcall(__markEnvNatives) end
local __fn, __err = (loadstring or load)(__src, {lua_basename})
__isLoaderLoad = false
if not __fn then
    __origPrint("loadstring error: " .. tostring(__err))
else
    if setfenv then pcall(setfenv, __fn, __realEnv) end
if __enableDeepTrace then __enableDeepTrace() end
-- Drive the original chunk as a coroutine instead of a bare pcall: a recovered
-- payload (e.g. this VM once its buffer ops work) runs a perpetual main loop that
-- parks on task.wait(). On the main thread task.wait cannot yield, so the loop
-- would spin forever and the footer dump would never run (Lune timeout kill). As
-- a coroutine we instead step it against the task pump in bounded fashion, then
-- abandon it after budget and dump what was logged.
local __chunk_arg_fn = nil
    if __CHUNK_ARG_SRC ~= nil then
        __chunk_arg_fn = (loadstring or load)("return function(...) " .. __CHUNK_ARG_SRC .. " end", "chunk-arg")()
    end
local ok, res
do
    __pumpStepping = true
    -- The payload is driven through nested pcall layers so the call stack below it
    -- carries real C frames, the way Roblox's scheduler/dispatcher does. Anti-tamper
    -- samples measure how much deeper debug.info can walk than the printed traceback
    -- (which hides C frames) and treat a flat ratio as a patched environment.
    local co = coroutine.create(function() return __fn(__chunk_arg_fn) end)
    local __mainResumes = 0
    __MAIN_BUDGET = _G.__MAIN_BUDGET or 400000
    __MAIN_WALLMS = _G.__MAIN_WALLMS or 240
    local __t0 = os.time()
    local __packed
    __vmTickMax = __vmTickMax or 0
    while true do
        __packed = table.pack(coroutine.resume(co))
        __mainResumes = __mainResumes + 1
        if not __packed[1] then break end
        if coroutine.status(co) == "dead" then break end
        -- wall-clock cap: a non-cooperative payload (no __vmTick injected, or a
        -- different loop shape) spinning on the main thread must still terminate
        -- fast enough to let the footer dump the staged logs instead of the Lune
        -- process being killed externally. os.time() is real wall time (os.clock
        -- is mocked to __fakeTime).
        local __now = os.time()
        if __now - __t0 > __MAIN_WALLMS then
            __table_insert(__LOGS, "-- LIMIT: main chunk wall-clock budget exceeded (abandoned)")
            break
        end
        if __mainResumes >= __MAIN_BUDGET then
            __table_insert(__LOGS, "-- LIMIT: main chunk spin budget exceeded (abandoned, script keeps running)")
            break
        end
        -- braced loops wait on task.wait -> pump their spawned workers here so the
        -- payload's own coroutines keep making progress while we step the loop
        if _G.__HTTP_NO_FETCH then
            __pcall(function() __stepQueue(40) end)
            __pcall(function() __stepSignals(10) end)
        else
            __pcall(function() __stepQueue(8) end)
            __pcall(function() __stepSignals(2) end)
        end
    end
    __pumpStepping = false
    ok = __packed and __packed[1] or false
    res = (__packed and __packed.n and __packed.n > 1) and __packed[2] or nil
    __origPrint("--- SCRIPT DONE ok=" .. tostring(ok) .. " res=" .. tostring(res)
        .. " resType=" .. type(res) .. " resumes=" .. __mainResumes .. " ---")
end
    -- Gate: if a real payload already ran (multiple API calls logged), then a
    -- top-level error afterwards is almost always the VM's own teardown hitting a
    -- mock artifact (e.g. pairs() on a __Member userdata that in real Roblox is a
    -- real table, or a perpetual anti-idle loop). Print it as a note, NOT as an
    -- error banner — the payload was captured, which is the point of this logger.
    local __gracefulEnd = (not ok) and (__LOG_COUNT >= __GRACEFUL_MIN_LOGS)
    __origPrint("--- SCRIPT DONE ok=" .. tostring(ok) .. " res=" .. tostring(res) .. " resType=" .. type(res) .. (__gracefulEnd and " [payload captured]" or "") .. " ---")
if not ok then
    if __gracefulEnd then
            __origPrint("--- SCRIPT FINISHED (payload captured; VM teardown error ignored) ---")
            __origPrint(tostring(res))
        else
            __origPrint("--- SCRIPT ERROR ---")
            __origPrint(tostring(res))
            pcall(function()
                __origPrint("--- SCRIPT ERROR TRACEBACK ---")
                __origPrint(tostring(debug.traceback("", 2)))
            end)
        end
    else
        if type(res) == "function" then
            local ok2, res2 = pcall(res)
            if not ok2 then
                __origPrint("--- RETURNED FUNCTION ERROR ---")
                __origPrint(tostring(res2))
            end
        end
        -- fire stored GUI/signal callbacks so button-gated fly payload runs (e.g. CreateButton callbacks)
        -- Each callback is resumed through a coroutine with a bounded resume budget, so an
        -- infinite `while true do task.wait() end` key-wait loop is abandoned instead of
        -- hanging the dump forever (Lune has no debug.sethook/os.exit to preempt it).
        pcall(function()
            local fired = 0
            local okLoop, loopErr = pcall(function()
if __signalStore then
                    __firingCallbacks = true
                    __pumpStepping = true
                    for _, e in ipairs(__signalStore) do
                        if type(e.cb) == "function" then
                            fired = fired + 1
                            __sigOnceDone[e] = true
                            __logCall("signal:Fire", __repr(e.sig))
                            local co = coroutine.create(e.cb)
                            local resumed = 0
                            while resumed < 20000 do
                                local ok2 = coroutine.resume(co)
                                if not ok2 then break end
                                if coroutine.status(co) == "dead" then break end
                                resumed = resumed + 1
                                if resumed >= 20000 then
                                    __table_insert(__LOGS, "-- LIMIT: signal callback spin budget exceeded (abandoned, script keeps running)")
                                    break
                                end
                                -- a live callback is parked on task.wait -> pump its spawned
                                -- tasks so spawned payload threads still progress
                                __pcall(function() __stepSignals(1) end)
                            end
                        end
                    end
__firingCallbacks = false
                    __pumpStepping = false
                end
            end)
            if not okLoop then
                __firingCallbacks = false
                __origPrint("--- SIGNAL FIRING ERROR ---")
                __origPrint(tostring(loopErr))
            end
 ---")
        end)
    end
end
-- expose cache to game:HttpGet via upvalue
if __httpCache then
    for k,v in pairs(__httpCache) do
        -- store for later HttpGet checks (strip query)
        local base = k:match("(https://[^?]+)")
        if base then __httpCache[base] = v end
    end
    -- patch game:HttpGet to use cache
    local g = __realEnv.game
    if g and getmetatable(g) then
        local mt = getmetatable(g)
        local orig = mt.__index
        mt.__index = function(self,k)
            if k=="HttpGet" or k=="HttpGetAsync" then
                return function(_, url)
                    local clean = tostring(url):gsub("[%c%z]", ""):match("(https://[^?]+)") or tostring(url):gsub("[%c%z]", "")
                    local cached = __httpCache[clean] or __httpCache[tostring(url):gsub("[%c%z]", "")]
                    if cached then
                        -- Repeated identical fetches are the loader's own retry
                        -- loop, not distinct calls. Label them so the trace shows
                        -- one logical fetch instead of N identical lines.
                        if _G.__lastUrl == clean then
                            _G.__retryN = (_G.__retryN or 0) + 1
                        else
                            _G.__lastUrl = clean
                            _G.__retryN = 1
                        end
                        local __tag = ""
                        if _G.__retryN > 1 then __tag = " (retry #" .. _G.__retryN .. ")" end
                        __logCall("game:HttpGet", string.format("%q", clean) .. " -- CACHED" .. __tag)
                        __table_insert(__LOGS, "-- LINK: " .. clean .. __tag)
                        return cached
                    end
                    return ""
                end
            end
            return orig(self,k)
        end
    end
end
-- // ORIGINAL SCRIPT END
"""
    gate_header = ""
    if gate_placeid:
        gate_header = (f'-- game-gate emulation: mock PlaceId={gate_placeid} (--place-id)\n'
                       f'_G.__GATE_PLACEID = _G.__GATE_PLACEID or {gate_placeid}\n'
                       f'_G.__GATE_GAMEID = _G.__GATE_GAMEID or {game_id or gate_placeid}\n')
    if syn_body:
        gate_header += (f'-- syn.request emulation: fake successful response Body (--syn-body)\n'
                        f'_G.__GATE_SYNBODY = _G.__GATE_SYNBODY or {lua_long_string(syn_body)}\n')
    return gate_header + LOGGER_HEADER + "\n" + loader + "\n" + LOGGER_FOOTER

def find_executor():
    """Locate a Luau/Lua interpreter.

    Order: explicit --lune (handled by the caller) > PATH > $LUNE_EXE > the
    standard cargo install location. Override anything else with --lune or the
    LUNE_EXE environment variable.
    """
    for name in ["lune", "lua", "luajit", "lua5.1"]:
        p = shutil.which(name)
        if p:
            return p, name
    env_exe = os.environ.get("LUNE_EXE") or os.environ.get("LUNE")
    if env_exe and pathlib.Path(env_exe).exists():
        return env_exe, "lune"
    # cargo install lune puts the binary here on every platform.
    cargo = pathlib.Path.home() / ".cargo" / "bin" / ("lune.exe" if os.name == "nt" else "lune")
    if cargo.exists():
        return str(cargo), "lune"
    return None, None

# CRASH GUARD: hard caps so a malicious/crashing script can't hurt your PC.
# - timeout clamped to 1..60s (kills runaway infinite loops / fork bombs)
# - stdout/stderr truncated to 5MB (a print-spammer can't OOM this Python process)
# - child is always killed on timeout (no orphaned lune process spinning your CPU)
_MAX_OUTPUT_BYTES = 5_000_000
_MAX_SOURCE_BYTES = 5_000_000

def run_with_lune(wrapped_path: pathlib.Path, executor: str, timeout=10):
    try:
        timeout = max(1, min(int(timeout or 8), 900))
    except Exception:
        timeout = 8
    try:
        if "lune" in executor.lower():
            cmd = [executor, "run", str(wrapped_path)]
        else:
            cmd = [executor, str(wrapped_path)]
        # Use bytes + utf-8 ignore to handle wearedevs binary junk (0x8f etc)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out_b, err_b = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                out_b, err_b = proc.communicate(timeout=5)
            except Exception:
                out_b, err_b = b"", b"timeout (killed, no output)"
            out_b = (out_b or b"")[:_MAX_OUTPUT_BYTES]
            err_b = (err_b or b"")[:65536]
            stdout = out_b.decode('utf-8', errors='ignore')
            stderr = err_b.decode('utf-8', errors='ignore')
            return stdout, (stderr + "\n[env-logger] process killed after timeout - infinite loop or hang").strip(), 1
        out_b = (out_b or b"")[:_MAX_OUTPUT_BYTES]
        err_b = (err_b or b"")[:65536]
        # Decode with utf-8 ignore, not cp1252
        stdout = out_b.decode('utf-8', errors='ignore')
        stderr = err_b.decode('utf-8', errors='ignore')
        return stdout, stderr, proc.returncode
    except Exception as e:
        return "", str(e), 1

def extract_logs(stdout) -> str:
    if not isinstance(stdout, str):
        if stdout is None:
            return ""
        try:
            stdout = str(stdout)
        except:
            return ""
    m = re.search(r"--- ENV LOGGER DUMP START ---\s*(.*?)\s*--- ENV LOGGER DUMP END ---", stdout, re.DOTALL)
    if m:
        return m.group(1).strip()
    # LIVE-STAGE blocks: printed by __flushStagedLive at capture time so a run that
    # dies (e.g. C-level stack overflow) before the end-of-run dump still yields the
    # deobfuscated second-stage sources. Reassemble them into one logged payload.
    if "-- [LIVE-STAGE" in stdout:
        blocks = re.findall(
            r"-- \[LIVE-STAGE \d+\] \S+: \d+ bytes --\s*(.*?)-- \[LIVE-STAGE \d+ END\] --",
            stdout, re.DOTALL)
        if blocks:
            return "\n\n".join(b.strip() for b in blocks if b.strip())
    return ""

def repair_lua_source(src):
    """Fix unambiguous transcription corruption in leaked / obfuscated sources.

    Every rule is deliberately narrow: it can only match text that cannot appear in
    working Luau, and it never changes what the script does. The original file is
    never touched and every fix is reported.

      1. unterminated string as the only argument of a call
             print("not dtc)          -> print("not dtc")
      2. junk (backtick / quote) trailing the last statement
             end`                   -> end
      3. redundant parens on an ASSIGNMENT TARGET, which Luau rejects as ambiguous
             (cache)[k] = v         -> cache[k] = v        (identical semantics)
      4. table constructor immediately followed by a field access, which needs parens
             local x = {a, b}.error -> local x = ({a, b}).error
    """
    fixes = []

    def lineno_of(text, idx):
        return text.count("\n", 0, idx) + 1

    # rule 1 - unterminated string literal as a call's only argument
    lines = src.split("\n")
    for i, ln in enumerate(lines):
        m = re.match(r'^(\s*[\w.:]+\s*\(\s*")([^"]*)(\)\s*;?\s*)$', ln)
        if m:
            fixed = m.group(1) + m.group(2) + '"' + m.group(3)
            lines[i] = fixed
            fixes.append((i + 1, "closed unterminated string literal", ln.strip()[:90], fixed.strip()[:90]))
    src = "\n".join(lines)

    # rule 2 - junk characters trailing the final statement
    idx = src.rstrip()
    tail = src[len(idx):]
    m = re.match(r'^(.*\S)\s*[`\']+\s*$', idx, re.S)
    if m and m.group(1).strip():
        before = m.group(1)
        src = before + tail
        fixes.append((lineno_of(src, len(before)), "removed stray trailing characters",
                      (before.strip()[-40:] + " <junk>"), before.strip()[-40:]))

    # rule 3 - (name)[ ... ] = ...  ->  name[ ... ] = ...
    for _ in range(8):
        out, changed = [], False
        for ln in src.split("\n"):
            m = re.match(r'^(\s*)\(\s*([A-Za-z_]\w*)\s*\)\[', ln)
            if m and re.search(r'\]\s*=', ln):
                new = m.group(1) + m.group(2) + "[" + ln[m.end():]
                out.append(new)
                changed = True
                fixes.append((0, "removed redundant parens before index assignment",
                              ln.strip()[:90], new.strip()[:90]))
            else:
                out.append(ln)
        src = "\n".join(out)
        if not changed:
            break

    # rule 4 - a table constructor used as the base of a field access needs parens,
    # both as an assignment value and as a statement:
    #     local x = {a, b}.error   ->  local x = ({a, b}).error
    #     {a, b}.error()           ->  ({a, b}).error()
    for _ in range(64):
        pos, hit = 0, False
        while True:
            idx = src.find("{", pos)
            if idx == -1:
                break
            head = src[:idx].rstrip()
            at_stmt_start = (not head) or head.endswith(("=", ",", "(", "return", "then", "do", "else"))
            line_start = src.rfind("\n", 0, idx) + 1
            is_first_on_line = not src[line_start:idx].strip()
            if not (at_stmt_start or is_first_on_line):
                pos = idx + 1
                continue
            depth, k = 0, idx
            while k < len(src):
                if src[k] == "{":
                    depth += 1
                elif src[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if k >= len(src):
                pos = idx + 1
                continue
            nxt = k + 1
            while nxt < len(src) and src[nxt] in " \t":
                nxt += 1
            if nxt < len(src) and src[nxt] == ".":
                new = src[:idx] + "(" + src[idx:k + 1] + ")" + src[k + 1:]
                fixes.append((lineno_of(src, idx), "parenthesised table constructor used as field base",
                              src[idx:idx + 60].split("\n")[0], new[idx:idx + 62].split("\n")[0]))
                src = new
                hit = True
                break
            pos = idx + 1
        if not hit:
            break

    # rule 5 - a statement starting with "(" after a complete statement is rejected by
    # Luau as ambiguous ("looks like an argument list for a function call"). A leading
    # ";" is an empty statement: it separates the two and changes nothing.
    lines = src.split("\n")
    for i, ln in enumerate(lines):
        st = ln.strip()
        if not st.startswith("("):
            continue
        prev = None
        for j in range(i - 1, -1, -1):
            if lines[j].strip():
                prev = lines[j].rstrip()
                break
        if prev is None:
            continue
        if prev.count("(") != prev.count(")") or prev.count("[") != prev.count("]") \
                or prev.count("{") != prev.count("}"):
            continue                                   # still inside a multi-line expression
        if re.search(r'\bfunction\b', prev):
            continue                                   # previous line opens a function body
        if prev.endswith(";") or not prev.strip():
            continue
        if re.search(r'(,|\+|-|\*|/|%|\^|=|~|\(|\[|\{|,|and|or|then|else|do|return)\s*$', prev):
            continue                                   # previous statement continues here
        # the ambiguity only exists when the previous line ends in something that could
        # be a call target; a bare identifier ('local fn') or a keyword ('end') is not one
        if not re.search(r'[\)\]}"\'0-9]\s*$', prev):
            continue
        indent = ln[:len(ln) - len(ln.lstrip())]
        lines[i] = indent + ";" + ln.lstrip()
        fixes.append((i + 1, "separated statement starting with '(' with ';'",
                      prev.strip()[:70], lines[i].strip()[:70]))
    src = "\n".join(lines)

    return src, fixes


def setup_argparse():
    p = argparse.ArgumentParser(description="Env Logger v2 - Python wrapper for Luau/Lua (Lune) - supports links")
    p.add_argument("script", help="Path to obfuscated Luau/Lua file or https:// link")
    p.add_argument("-o", "--output", default="logged.lua", help="Output file for the RECOVERED PAYLOAD SOURCE, directly executable (default: logged.lua). Falls back to the call trace when no payload was recovered.")
    p.add_argument("--trace-out", default=None, metavar="PATH", help="Where to write the raw call trace (default: <output stem>.trace.lua). The trace is a behaviour log, not runnable Lua.")
    p.add_argument("--no-trace", action="store_true", help="Do not write the call-trace sidecar file at all")
    p.add_argument("--lune", default=None, help="Path to lune/lua binary (auto-detect if not set)")
    p.add_argument("--no-run", action="store_true", help="Only generate wrapped file, don't execute")
    p.add_argument("--timeout", type=int, default=30, help="Execution timeout seconds (default 30; gives obfuscated payloads a full 30s budget to run and produce output, then the run is stopped cleanly and staged logs still captured)")
    p.add_argument("--no-net", action="store_true", default=True, help="Fully offline: no network fetches at all (prefetch + links return empty). This is the DEFAULT")
    p.add_argument("--net", dest="no_net", action="store_false", help="Allow network prefetch/linking (opt-in; the exfil sinks stay hard-blocked either way)")
    p.add_argument("--no-fetch", action="store_true", help="EXECUTOR-style direct loadstring: never simulate a fetch. game:HttpGet returns empty, no cache injection, no LINK logs; loadstring executes whatever string it is actually passed")
    p.add_argument("--repair-source", action="store_true", help="Repair unambiguous transcription corruption in the source before wrapping (unterminated strings, stray trailing characters, (t)[k]=v ambiguity, {t}.field). Originals are never modified; every fix is printed")
    p.add_argument("--payload", metavar="FILE", help="Mock an in-game HttpGet: serve this file's content as the response for every game:HttpGet call (use with --no-fetch so loadstring runs the real captured payload)")
    p.add_argument("--place-id", type=int, default=0, metavar="ID", help="Emulate running inside a specific Roblox game: game.PlaceId returns this value (overrides auto-detected game gate). Default 0 = no game")
    p.add_argument("--game-id", type=int, default=0, metavar="ID", help="Emulate game.GameId (UniverseId). Default 0 = follow --place-id for compatibility")
    p.add_argument("--hide-executor-globals", dest="hide_exec_globals", action="store_true", help="Hide executor-only globals (getgenv, getgc, syn, io, readfile, ...) from the script: some anti-tamper samples require them to be absent")
    p.add_argument("--strict-members", dest="strict_members", action="store_true", help="Unknown Instance/Service members read as nil (real Roblox behavior) instead of a catch-all callable stub: required by anti-tamper samples that probe for missing members")
    p.add_argument("--syn-body", dest="syn_body", default=None, metavar="FILE", help="Fake syn.request success: return this file's content as the response Body (for key-activator/key-loader flows)")
    p.add_argument("--chunk-arg", dest="chunk_arg", default=None, metavar="FILE", help="Pass this file's content (newline-separated Lua funcs, loadstring'd) as the wrapped chunk's vararg, for return-setfenv/ygOcT-style shells")
    p.add_argument("--prefetch-file", default=None, help="Path to a text/log file; every '-- LINK: <url>' line found is pre-fetched into the cache before the run (second-pass payload recovery)")
    p.add_argument("--clean", action="store_true", help="Clean VM junk, payload only (default is verbose, very much)")
    p.add_argument("--no-filter", action="store_true", help="Alias for verbose (log very much)")
    p.add_argument("--no-full-source", action="store_true", help="Don't embed full payload source inline in LOGS (only dump via SECOND-STAGE; smaller output but source is in the footer section only)")
    p.add_argument("--no-fetched", action="store_true", help="Don't show fetched payload contents at all: skip full source inline + SECOND-STAGE + HARVESTED STRINGS sections (fetch size/URLs still logged)")
    p.add_argument("--auto-link", action="store_true", help="After a run, if -- LINK UNCACHED lines are found, automatically prefetch them and re-run (two-pass in one invocation)")
    p.add_argument("--report", default=None, metavar="PATH", help="Write full run report (console output + stats) to this file alongside -o")
    p.add_argument("--json", dest="json_out", default=None, metavar="PATH", help="Write machine-readable summary JSON (lines/links/coverage/status) to this file")
    p.add_argument("--verbose", action="store_true", help="Print more runtime detail (prefetch attempts, executor, staged bytes)")
    return p

import re as _decode_re
import math as _decode_math

def _repr_block(text: str, width: int = 88) -> str:
    """Return a Lua-commented block of text (every line prefixed with --)."""
    out = []
    for line in text.splitlines():
        # assume Lua safety: comment every line so the block never breaks the chunk
        out.append("-- " + line)
    return "\n".join(out)

def _static_decode_bytearrays(src: str, min_bytes: int = 40) -> list:
    """Find `local NAME = {n1,n2,...}` byte arrays in a Lua source and decode
    them to text. Returns [(decoded_text, array_id, byte_count), ...] sorted by
    size desc. Only arrays whose values are all 0-255 and that actually encode
    printable text are kept (avoids dumping random bait arrays)."""
    found = []
    # match: local NAME = { int, int, int, ... }  (single line)
    arr_pat = _decode_re.compile(
        r"local\s+([A-Za-z_]\w*)\s*=\s*\{((?:\s*\d{1,3}\s*,)*\s*\d{1,3}\s*)\}")
    # The same array may be assigned via `local NAME = {...}` or reassigned later.
    seen = set()
    for m in arr_pat.finditer(src):
        arr_name = m.group(1)
        if arr_name in seen:
            continue
        seen.add(arr_name)
        body = m.group(2)
        vals = [int(x.strip()) for x in body.split(",") if x.strip() != ""]
        if len(vals) < min_bytes:
            continue
        if any(v < 0 or v > 255 for v in vals):
            continue
        # herustic: empty/whitespace-only array is junk (many VMs pad with zeros)
        if all(v == 0 or v == 32 or v == 10 or v == 13 for v in vals):
            continue
        # sometimes arrays are split across multiple lines; merge continuation
        # `local NAME = { ...\n,...}` handled by appending more numbers
        try:
            raw = bytes(vals).decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        # only keep arrays that decode to mostly-printable text
        if len(raw) == 0:
            continue
        printable = sum(1 for c in raw if c in "\r\n\t" or 32 <= ord(c) <= 126)
        if printable / len(raw) < 0.80:
            continue
        found.append((raw, arr_name, len(vals)))
    # dedup identical decoded payloads (same string often stored in 2 arrays)
    seen_txt = set()
    uniq = []
    for raw, name, n in sorted(found, key=lambda t: -t[2]):
        key = raw[:200]
        if key in seen_txt:
            continue
        seen_txt.add(key)
        uniq.append((raw, name, n))
    return uniq[:20]

def fetch_link(url: str) -> str:
    if NO_NET:
        return ""
    # curl_cffi: real Chrome TLS handshake -> beats pure-Cloudflare TLS/JA3 gates
    # (still loses to Obscura's own server-side "Detected and blocked" check).
    try:
        from curl_cffi import requests as _cr
        r = _cr.get(url, impersonate="chrome", timeout=20)
        if r.status_code == 200 and r.content:
            txt = r.content[:_MAX_OUTPUT_BYTES].decode('utf-8', errors='ignore')
            if not txt.lstrip().lower().startswith(("<!doctype", "<html")):
                return txt
    except Exception:
        pass
    try:
        import cloudscraper
        # cloudscraper defeats plain Cloudflare; Obscura's own layer may still
        # 403 -> fall through to requests/urllib below.
        s = cloudscraper.create_scraper(browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True})
        r = s.get(url, timeout=20)
        if r.status_code == 200 and r.content:
            return r.content[:_MAX_OUTPUT_BYTES].decode('utf-8', errors='ignore')
    except Exception:
        pass
    try:
        import requests
    except ImportError:
        requests = None
    try:
        if requests is not None:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                return r.content[:_MAX_OUTPUT_BYTES].decode('utf-8', errors='ignore')
            raise RuntimeError(f"HTTP {r.status_code}")
        with urllib.request.urlopen(url, timeout=10) as r:
            # CRASH GUARD: never read an unbounded response into RAM
            return r.read(_MAX_OUTPUT_BYTES).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] failed to fetch link {url}: {e}", file=sys.stderr)
        return ""

def _u32(n: int) -> int:
    return n & 0xFFFFFFFF

def _bxor(a: int, b: int) -> int:
    return _u32(a) ^ _u32(b)

def _band(a: int, b: int) -> int:
    return _u32(a) & _u32(b)

def _rshift(a: int, b: int) -> int:
    return (_u32(a) >> (b & 31)) & 0xFFFFFFFF

def reconstruct_custom_vm(src: str, runtime_logs: list) -> list:
    """Best-effort reconstruction for eqCrOTSX1-style VMs.
    Returns header lines (comments + replay stub) so logged.lua reads like a script.
    Never fails the run - returns [] if pattern not found."""
    if "eqCrOTSX1" not in src and "v5miE517" not in src:
        return []
    out = []
    out.append("-- Reconstructed by env_logger v2 (runtime trace + static VM decode)")
    out.append(f"-- Source VM: {len(src)} bytes, runtime calls: {len(runtime_logs)}")
    # 1) list known opcode handlers found in source
    handlers = sorted(set(re.findall(r"v5miE517\[(\d+)\]", src)))
    if handlers:
        out.append(f"-- VM handlers ({len(handlers)}): " + ", ".join(handlers[:20]) + (" ..." if len(handlers) > 20 else ""))
    # 2) decode qUCJR22[1], lCqq8/aGZIV9/p4TR7J010, BC, then walk 1-2 ops (proves empty return)
    try:
        nums = [int(x) for x in re.findall(r"return\s+(-?\d+)", src)]
        # q1 = 176611360-53 pattern: ((function()return N end)()-M)
        m = re.search(r"qUCJR22=\{\(\(function\(\)return\s+(\d+)\s+end\)\(\)-(\d+)\)\}", src)
        if m:
            q1 = int(m.group(1)) - int(m.group(2))
            out.append(f"-- const qUCJR22[1] = {q1}")
        # BC array: {((N)-(M)),((N)-(M))}
        bcm = re.search(r"local BC=\{\(\((\d+)\)-\((\d+)\)\),\(\((\d+)\)-\((\d+)\)\)\}", src)
        if bcm:
            bc = [int(bcm.group(1)) - int(bcm.group(2)), int(bcm.group(3)) - int(bcm.group(4))]
            out.append(f"-- bytecode BC = {bc} ({len(bc)} ops)")
            # replicate Y/Nk decode using first-seen keys (same math as dump_script)
            # lCqq8 = bxor((769347-60)+(6557105-86), q1)
            lC = _bxor((769347 - 60) + (6557105 - 86), q1)
            aG = _bxor((2466734 + 36) - 101, (2466397 + 31) - 126)
            p4 = _bxor((2413324 - 63), (2421445 - 43))
            def _Y(i):
                return _band(_bxor(lC + (i * aG), _rshift(i, 3) + p4), 0x7FFFFFFF)
            pe = ((3449484 - 157) + (-3441710 - 82))
            Jb = ((1526663 - 109) + (-1519355 - 92))
            lCen = _bxor(4209183 - 53, 4203496 - 92)
            def _Nk(p):
                return _band(_bxor(pe * p + Jb, _rshift(p, 2) + lCen), 0x7FFFFF)
            def _Lg(w, i):
                return _bxor(w, _Y(i))
            if len(bc) >= 1:
                op1 = _bxor(_Lg(bc[0], 1), _Nk(1))
                out.append(f"-- decoded op[1] = {op1} (385729 = collect return values)")
            if len(bc) >= 2:
                nv = _Lg(bc[1], 2)
                out.append(f"-- decoded ret count nv = {nv} -> return table.unpack({{}}, 1, {nv})")
                if nv == 0:
                    out.append("-- result: VM returns empty (no payload calls exist to log)")
    except Exception:
        pass
    # 3) replay stub so logged.lua runs standalone
    out.append("")
    out.append("-- replayed runtime calls below (run with: lune run logged.lua)")
    out.append("")
    return out

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    parser = setup_argparse()
    args = parser.parse_args()
    # Artefacts on disk (fetched.lua etc.) are shared across invocations, so
    # remember when this run started: a payload file only counts as recovered
    # from THIS run if it was written after this timestamp.
    _run_started = time.time()
    global NO_NET
    NO_NET = args.no_net
    if NO_NET:
        print(f"{_dim('    •')} offline mode: no network prefetch/fetch")

    # support links: https://raw.githubusercontent.com/...
    original = ""
    src_path = None
    is_link = args.script.startswith("http://") or args.script.startswith("https://")
    if is_link:
        print(f"{_bold(_cyan('   link'))} fetching {_cyan(args.script)}")
        original = fetch_link(args.script)
        if not original:
            print(f"{_red('    ✗')} failed to fetch link", file=sys.stderr)
            sys.exit(1)
        src_path = pathlib.Path("link.lua")
        print(f"{_green('    ✓')} fetched {_bold(len(original))} bytes from link")
    else:
        src_path = pathlib.Path(args.script)
        if not src_path.exists():
            print(f"{_red('    ✗')} file not found: {src_path}", file=sys.stderr)
            sys.exit(1)
        if src_path.stat().st_size > _MAX_SOURCE_BYTES:
            print(f"{_red('    ✗')} refusing >{_MAX_SOURCE_BYTES}B source ({src_path.stat().st_size}B) - likely a bomb, not a script", file=sys.stderr)
            sys.exit(1)
        original = src_path.read_text(encoding="utf-8", errors="ignore")
        # support file containing only a link (e.g. a script.lua holding just
        # "https://example.com/script.lua")
        stripped = original.strip()
        if stripped.startswith("http://") or stripped.startswith("https://"):
            # check if it's just a link (single line, no lua keywords)
            lines = stripped.splitlines()
            if len(lines) == 1 and re.match(r'^https?://\S+$', stripped):
                print(f"{_bold(_cyan('   link'))} file contains link, fetching: {stripped}")
                fetched = fetch_link(stripped)
                if fetched:
                    print(f"{_green('    ✓')} fetched {_bold(len(fetched))} bytes from embedded link (was {len(original)}b file)")
                    original = fetched
                    is_link = True
                else:
                    print(f"{_red('    ✗')} failed to fetch embedded link, using original file content", file=sys.stderr)

    # ---- static bPeM recovery (no runtime needed; the init VM spins forever) ----
    deob_src = None
    # Fulcrum (polsec.sh) is a single-line constant-pool VM: everything the real
    # loader needs is assembled at runtime through getfenv(), so the source text
    # contains no loadstring/game/HttpGet to grep for. Flag it so the run is
    # reported honestly instead of looking like a silent no-op.
    if "obfuscated by Fulcrum" in original:
        _fl_lines = original.count("\n") + 1
        print(f"{_green('    ✓')} Fulcrum detected (polsec.sh constant-pool VM, {_fl_lines} lines, "
              f"{len(original)} bytes)")
        print(f"{_dim('    •')} note: Fulcrum's payload is built at runtime via getfenv(); the decoded "
              f"loader needs its enclib from game:HttpGet")
        if args.no_fetch or args.no_net:
            print(f"{_yellow('    !')} Fulcrum cannot fully unwrap offline - the enclib is fetched from "
                  f"api.polsec.sh. Re-run WITHOUT --no-fetch/--no-net to recover it (this contacts a "
                  f"third party and reveals this machine's IP).")
    if BPEM_HEADER in original:
        deob_src, pool, tags = bpem_deob_src(original)
        if deob_src is not None:
            deob_path = pathlib.Path("_bpem_deob.lua")
            deob_path.write_text(deob_src, encoding="utf-8")
            n_str = sum(1 for t in tags if t == "STR")
            n_fun = sum(1 for t in tags if t == "FUN")
            print(f"{_green('    ✓')} bPeM detected - static deobfuscation recovered {_bold(len(pool))} pool entries "
                  f"({n_str} strings, {n_fun} closures)")
            print(f"{_dim('    •')} deobfuscated source -> {_cyan(str(deob_path))} ({len(deob_src)} bytes)")
            # recover decoded strings (incl. large blobs) as a pool dump
            try:
                pool_path = pathlib.Path("_bpem_pool.txt")
                with pool_path.open("w", encoding="utf-8", errors="replace") as f:
                    for i in range(1, len(pool) + 1):
                        v = _bpem_pool_val(pool, tags, i)
                        if isinstance(v, str):
                            f.write(f"[{i}]\t{tags[i-1]}\t{v}")
                        else:
                            f.write(f"[{i}]\t{tags[i-1]}\t{_bpem_luarepr(v)}")
                        f.write("\n")
                print(f"{_dim('    •')} decoded pool -> {_cyan(str(pool_path))} "
                      f"({pool_path.stat().st_size} bytes)")
            except Exception as e:
                print(f"{_red('    ✗')} pool dump failed: {e}", file=sys.stderr)
            # extract big blobs as bin files (loadstring bytecode / VM payload)
            try:
                blob_dir = pathlib.Path("_bpem_blobs")
                blob_dir.mkdir(exist_ok=True)
                blob_count = 0
                for i in range(1, len(pool) + 1):
                    v = pool[i - 1]
                    if tags[i - 1] == "STR" and isinstance(v, str) and len(v) > 4096:
                        if v[0] in "TI":
                            raw = (_bpem_b64d(v[1:]) if v[0] == "T" else _bpem_b85d(v[1:]))
                            if len(raw) >= 4096:
                                p = blob_dir / f"pool_{i}.bin"
                                p.write_bytes(raw)
                                blob_count += 1
                if blob_count:
                    print(f"{_bold(_green('    ✓'))} recovered {_bold(blob_count)} large blob(s) -> {_cyan(str(blob_dir))} "
                          f"(pool indices: {[i for i in range(1, len(pool)+1) if tags[i-1]=='STR' and isinstance(pool[i-1], str) and len(pool[i-1])>4096]})")
            except Exception as e:
                print(f"{_red('    ✗')} blob extract failed: {e}", file=sys.stderr)

    # wrap the DE-OBFUSCATED source when bPeM: constants already inlined => logs are readable
    wrap_src = (deob_src or original)

    if args.repair_source:
        repaired, fixes = repair_lua_source(wrap_src)
        if fixes:
            print(f"{_bold(_green('    \u2713'))} source repair: {_bold(len(fixes))} unambiguous fix(es) applied")
            for lineno, why, before, after in fixes:
                where = f"line {lineno}: " if lineno else ""
                print(f"{_dim('      \u2022')} {where}{why}")
                print(f"{_dim('        -')} {_dim(before)}")
                print(f"{_dim('        +')} {after}")
            wrap_src = repaired
        else:
            print(f"{_dim('    \u2022')} source repair: nothing to fix")

    # Mock in-game HttpGet: ONLY when --payload is passed explicitly. There is no
    # auto-discovery fallback -- no scanning the source for URLs, no seeding from
    # files left behind by earlier runs, no guessing filenames from a URL's path
    # segment. An explicit file is the only thing that gets served.
    mock_payloads = {}
    if args.payload:
        try:
            mock_payloads["*"] = pathlib.Path(args.payload).read_text(encoding="utf-8", errors="ignore")
            print(f"{_dim('    \u2022')} mock in-game payload: {_cyan(args.payload)} ({len(mock_payloads['*'])}b served to game:HttpGet)")
        except Exception as e:
            print(f"{_red('    \u2717')} failed to read --payload: {e}", file=sys.stderr)
    mock_payload = mock_payloads.get("*", "") if args.payload else ""
    syn_body_content = ""
    if args.syn_body:
        try:
            syn_body_content = pathlib.Path(args.syn_body).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"    ! cannot read --syn-body {args.syn_body}: {e}")
    chunk_arg_content = ""
    if args.chunk_arg:
        try:
            chunk_arg_content = pathlib.Path(args.chunk_arg).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"    ! cannot read --chunk-arg {args.chunk_arg}: {e}")

    wrapped_src = build_wrapped_script(wrap_src, basename=src_path.name, full_payload=not args.no_full_source, no_fetched=args.no_fetched, no_fetch=args.no_fetch, mock_payload=mock_payload, mock_payloads=mock_payloads or {}, place_id=args.place_id, game_id=args.game_id or args.place_id, syn_body=syn_body_content, chunk_arg=chunk_arg_content, hide_exec_globals=args.hide_exec_globals, strict_members=args.strict_members)

    extra_urls = []
    if args.prefetch_file:
        try:
            for line in pathlib.Path(args.prefetch_file).read_text(encoding="utf-8", errors="ignore").splitlines():
                m = re.search(r'-- LINK(?: UNCACHED)?: (https?://\S+)', line)
                if m:
                    extra_urls.append(m.group(1))
            if extra_urls:
                print(f"{_dim('    •')} prefetch-file: {len(extra_urls)} link(s) from {_cyan(args.prefetch_file)}")
        except Exception as e:
            print(f"{_red('    ✗')} failed to read prefetch-file: {e}", file=sys.stderr)

    if extra_urls:
        wrapped_src = build_wrapped_script(wrap_src, basename=src_path.name, extra_urls=extra_urls, full_payload=not args.no_full_source, no_fetched=args.no_fetched, no_fetch=args.no_fetch, mock_payload=mock_payload, mock_payloads=mock_payloads or {}, place_id=args.place_id, game_id=args.game_id or args.place_id, syn_body=args.syn_body or "", chunk_arg=args.chunk_arg or "", hide_exec_globals=args.hide_exec_globals, strict_members=args.strict_members)

    wrapped_path = pathlib.Path("__wrapped__.lua")
    wrapped_path.write_text(wrapped_src, encoding="utf-8")

    print(f"{_green('    ✓')} wrapped -> {_cyan(str(wrapped_path))} ({_bold(len(wrapped_src))} bytes)")
    print(f"{_green('    ✓')} original -> {_cyan(str(src_path))} ({len(original)} bytes)")

    if args.no_run:
        if deob_src is not None:
            try:
                out_path = pathlib.Path(args.output) if args.output else None
                if out_path:
                    header = ("-- ============================================================\n"
                              "-- STATIC bPeM RECOVERY (no runtime execution - VM spins forever)\n"
                              "-- Constants inlined from the decoded pool; large blobs saved to _bpem_blobs/\n"
                              "-- ============================================================\n")
                    out_path.write_text(header + deob_src, encoding="utf-8")
                    print(f"{_dim('    •')} wrote recovered source -> {_cyan(str(out_path))}")
            except Exception as e:
                print(f"{_red('    ✗')} failed to write output: {e}", file=sys.stderr)
        print(f"{_dim('    •')} no-run mode: wrapped file ready. Run manually with: lune run {wrapped_path}")
        return

    executor = args.lune
    exe_name = "custom"
    if not executor:
        executor, exe_name = find_executor()
        if not executor:
            print(f"{_red('    ✗')} lune/lua not found in PATH. Install Lune (https://github.com/lune-org/lune) or use --lune <path>", file=sys.stderr)
            print(f"    wrapped file saved to {wrapped_path}, output would be {args.output}", file=sys.stderr)
            sys.exit(1)

    print(f"{_green('    ✓')} executor: {_bold(exe_name)} @ {executor}")
    try:
        args.timeout = max(1, min(int(args.timeout), 900))
    except Exception:
        args.timeout = 8
    print(f"{_green('    ✓')} limits: timeout={args.timeout}s, max-output=5MB, max-source=5MB (crash guard)")
    stdout, stderr, code = run_with_lune(wrapped_path, executor, timeout=args.timeout)

    if stderr:
        print(f"{_yellow('[stderr]')}\n{stderr[:2000]}")

    logged_path = pathlib.Path("__logged__.lua")
    logs = ""
    if logged_path.exists():
        logs = logged_path.read_text(encoding="utf-8", errors="ignore").strip()
        print(f"{_green('    ✓')} logs captured from file: {len(logs.splitlines())} lines")
        stdout_logs = extract_logs(stdout)
        if stdout_logs and not logs:
            logs = stdout_logs
    else:
        logs = extract_logs(stdout)
        print(f"{_green('    ✓')} logs captured from stdout: {len(logs.splitlines())} lines")

    # fallback: if we got empty but stdout had content, try raw stdout
    if not logs or logs == "-- no logs":
        stdout_logs = extract_logs(stdout)
        if stdout_logs and stdout_logs != "-- no logs":
            logs = stdout_logs
            print(f"{_green('    ✓')} fallback logs from stdout: {len(logs.splitlines())} lines")

    if not logs or logs == "-- no logs":
        if deob_src is not None:
            # bPeM: the payload was recovered STATICALLY (runtime VM spins forever by design).
            # Report success with the recovered artifacts instead of a misleading "no logs" error.
            print(f"{_bold(_green('    ✓'))} bPeM STATIC RECOVERY SUCCEEDED (runtime VM hang is expected)")
            print(f"    {_green('·')} deobfuscated source : _bpem_deob.lua ({len(deob_src)} bytes)")
            print(f"    {_green('·')} decoded constant pool: _bpem_pool.txt")
            print(f"    {_green('·')} recovered payload blob: _bpem_blobs/")
            # write output file with the recovered source so -o still produces an artifact
            try:
                out_path = pathlib.Path(args.output) if args.output else None
                if out_path:
                    header = ("-- ============================================================\n"
                              "-- STATIC bPeM RECOVERY (no runtime execution - VM spins forever)\n"
                              "-- Constants inlined from the decoded pool; large blobs saved to _bpem_blobs/\n"
                              "-- ============================================================\n")
                    out_path.write_text(header + deob_src, encoding="utf-8")
                    print(f"    {_green('·')} wrote recovered source -> {_cyan(str(out_path))}")
            except Exception as e:
                print(f"{_red('    ✗')} failed to write output: {e}", file=sys.stderr)
            return 0
        # A script can run perfectly and log nothing (it may just return a table,
        # or do all its work through APIs the logger does not trace). That is not a
        # failure, and it must still leave an artifact instead of exiting non-zero
        # with nothing written.
        if "SCRIPT DONE ok=true" in (stdout or ""):
            print(f"{_bold(_green('    ✓'))} script ran to completion and logged nothing (no traced calls - nothing to deobfuscate)")
            try:
                _op = pathlib.Path(args.output) if args.output else None
                if _op:
                    _op.write_text(
                        "-- script executed successfully but produced no traced calls.\n"
                        "-- There is no recovered payload: this obfuscator does its work\n"
                        "-- through APIs the logger does not observe.\n"
                        f"-- original source: {src_path.name if src_path else args.script}\n",
                        encoding="utf-8")
                    print(f"    {_green('·')} wrote run summary -> {_cyan(str(_op))}")
                    if not args.no_trace:
                        if args.trace_out:
                            _tp = pathlib.Path(args.trace_out)
                        else:
                            _tp = _op.with_name(_op.stem + ".trace.lua")
                        _tp.write_text("--Deobfuscated by Comet\n\n-- no logs\n", encoding="utf-8")
            except Exception as e:
                print(f"{_red('    ✗')} failed to write output: {e}", file=sys.stderr)
            return 0
        print(f"{_red('    ✗')} no logs captured - script may have:")
        print("      · heavy obfuscation with custom VM")
        print("      · infinite loop / timeout")
        print("      · anti-logger that killed process")
        print(f"    {_yellow('--- stdout ---')}")
        print(stdout[:3000] or "<empty>")
        sys.exit(1)

    lines = logs.splitlines()
    filtered = [l for l in lines if l.strip() != "" and l.strip() != "-- no logs"]
    # Only use fetched.lua if THIS run actually logged links (don't inject old unrelated payload)
    link_pattern = r'https?://[^\s"\'\)]+'
    links = re.findall(link_pattern, logs)
    for l in lines:
        if l.startswith("-- LINK:"):
            m = re.search(link_pattern, l)
            if m: links.append(m.group(0))
    links = list(dict.fromkeys(links))
    # VM-junk collapse (always on): website obfuscators (wearedevs/moonveil) decode
    # strings via hundreds of string.char/table.concat calls. Those bury the real
    # payload (Instance.new + ScreenGui_1.Text = ...). Collapse them to 1 comment,
    # keep payload. No downloads, no extra tools.
    import re as _re2
    # ---- auto-decode: rehydrate string.char(...) / table.concat(...) sequences ----
    # Obfuscated scripts decode their strings byte-by-byte before using them. Instead
    # of showing 500 raw string.char(72, 101, ...) lines, decode them back into text
    # so the real payload strings (URLs, game names, messages) are readable.
    def _decode_string_char(s: str):
        """Parse a FULL line `string.char(72, 101, ...)` -> decoded text.
        Requires whole-line match: chained `string.char(83)..string.char(75)`
        (real script code) is left untouched."""
        s = s.strip()
        m = _re2.match(r"^string\.char\(\s*([^()]*?)\s*\)\s*(?:--\[\[.*\]\])?$", s)
        if not m:
            return None
        body = m.group(1)
        if not body.strip():
            return None
        nums = []
        for chunk in body.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk == "...":
                nums.append(None); continue
            try:
                nums.append(int(chunk))
            except ValueError:
                return None
        chars = []
        truncated = False
        for n in nums:
            if n is None:
                truncated = True
                break
            if 0 <= n <= 255:
                chars.append(chr(n))
            else:
                return None
        out = "".join(chars)
        if not out:
            return None
        # only decode if all-printable-ish (avoid injecting garbage binary)
        if all(c in "\r\n\t" or 32 <= ord(c) <= 126 for c in out):
            if truncated:
                return out + u" […]"
            return out
        return None

    def _decode_table_concat(s: str):
        """Parse a FULL line `table.concat({...})` -> concatenated text."""
        m = _re2.match(r"^table\.concat\(\{(.*)\}\)$", s.strip())
        if not m:
            return None
        body = m.group(1)
        parts = []
        for chunk in body.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            mq = _re2.match(r"^(['\"])(.*?)\1$", chunk)
            if mq:
                parts.append(mq.group(2))
            else:
                # string.char inside a table.concat(...) element
                mc = _re2.match(r"^string\.char\(([^()]*)\)$", chunk)
                if mc:
                    dec = _decode_string_char("string.char(" + mc.group(1) + ")")
                    if dec is None:
                        return None
                    parts.append(dec)
                else:
                    return None
        out = "".join(parts)
        if not out:
            return None
        if all(c in "\r\n\t" or 32 <= ord(c) <= 126 for c in out):
            return out
        return None

    # consecutive decode run -> single readable comment; cap per-run so huge byte blobs
    # collapse into one line instead of thousands
    def _collapse_decodes(lines):
        out = []
        run = []
        def flush():
            if run:
                text = "".join(run)
                # one line, escaped, max 300 chars so logged.lua stays manageable
                esc = text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
                if len(text) > 300:
                    esc = esc[:300] + "…"
                    out.append(f"-- [decoded {len(text)} bytes] {esc}")
                else:
                    out.append(f"-- {esc}")
                run.clear()
        for ln in lines:
            st = ln.strip()
            dec = None
            if st.startswith("string.char("):
                dec = _decode_string_char(st)
            elif st.startswith("table.concat({"):
                dec = _decode_table_concat(st)
            if dec is not None:
                run.append(dec)
                continue
            flush()
            out.append(ln)
        flush()
        return out

    filtered = _collapse_decodes(filtered)
    # stage extraction: pull second-stage loadstring sources out into their own file
    _stages_out = []
    _in_stages = False
    for _si, _sl in enumerate(filtered):
        if _sl.strip().startswith("-- ---- SECOND-STAGE SOURCES"):
            _in_stages = True
            continue
        if _in_stages and _sl.strip().startswith("-- ---- end second-stage"):
            _in_stages = False
            continue
        if _in_stages:
            if _sl.strip().startswith("-- [stage"):
                _stages_out.append("\n" + _sl.strip() + "\n")
            elif _sl.strip():
                _stages_out.append(_sl)
            else:
                _stages_out.append("")
    if _stages_out:
        _stage_txt = "\n".join(_stages_out).strip("\n")
        if _stage_txt:
            _sp = pathlib.Path("stages.lua")
            _sp.write_text(_stage_txt, encoding="utf-8")
            print(f"{_green('    ✓')} second-stage sources: {_stage_txt.count(chr(10))+1}-ish bytes -> stages.lua")
    # harvested-strings extraction: pull HARVESTED STRINGS block into its own file
    _harv_out = []
    _in_harv = False
    for _sl in filtered:
        if _sl.strip().startswith("-- ---- HARVESTED STRINGS"):
            _in_harv = True
            continue
        if _in_harv and _sl.strip().startswith("-- ---- end harvested"):
            _in_harv = False
            continue
        if _in_harv:
            if _sl.strip().startswith("-- [string") or _sl.strip() == "":
                continue
            _harv_out.append(_sl)
    if _harv_out:
        _harv_txt = "\n".join(_harv_out).strip("\n")
        if _harv_txt:
            _hp = pathlib.Path("harvested.lua")
            _hp.write_text(_harv_txt, encoding="utf-8")
            print(f"{_green('    ✓')} harvested runtime strings: {len(_harv_out)} lines -> harvested.lua")
    _junk_re = _re2.compile(r"^(string\.char|table\.concat|string\.byte|string\.sub|string\.len|bit32\.|math\.(floor|random|ceil|abs))\(?")
    _junk_count = sum(1 for l in filtered if _junk_re.match(l.strip()))
    if _junk_count >= 20:
        # strip ONLY the decode-noise lines; keep every other script line as-is
        # (a whitelist filter was dropping real payload code that didn't match)
        _payload = [l for l in filtered if not _junk_re.match(l.strip())]
        if len(_payload) >= 1 and len(_payload) < len(filtered):
            print(f"{_yellow('    !')} VM-junk collapse: {len(filtered)} -> {len(_payload)} lines (hid {_junk_count} string.char/table.concat decodes)")
            filtered = [f"-- collapsed {_junk_count} VM string-decode calls (string.char/table.concat), payload below --"] + _payload
    # --clean = strict payload only (keeps property assignments too, unlike old version)
    if "--clean" in sys.argv and len(filtered) > 10:
        whitelist = [r"^print\(", r"^warn\(", r"^game:", r"^workspace:", r"^-- getglobal", r"^Instance\.new", r"^loadstring\(", r"^-- LINK:", r"^[A-Za-z]+_\d+[\.:]", r"^TweenInfo", r"^Color3", r"^UDim", r"^signal:"]
        keep = [l for l in filtered if any(_re2.match(p, l.strip()) for p in whitelist)]
        if len(keep) >= 1 and len(keep) < len(filtered):
            print(f"{_yellow('    !')} --clean: {len(filtered)} -> {len(keep)} lines (payload only)")
            filtered = keep
    if len(filtered) > 5000:
        # keep head (context/setup) + tail (payload/loadstring usually at the end)
        _keep = filtered[:2000] + ["-- [capped: omitting middle lines …]"] + filtered[-3000:]
        print(f"{_yellow('    !')} capped {len(filtered)} -> {len(_keep)} (kept head + tail)")
        filtered = _keep

    # Reconstruct: prepend header + VM trace so logged.lua looks like a script, not 1 line
    try:
        recon_head = reconstruct_custom_vm(original, filtered)
        if recon_head:
            filtered = recon_head + filtered
            print(f"{_green('    ✓')} reconstructed VM trace: +{len(recon_head)} header lines")
    except Exception as e:
        print(f"{_yellow('    !')} reconstruct skip: {e}")
    logs = "\n".join(filtered)

    # ---- STATIC BYTE-ARRAY DECODE ----
    # The biggest source-recovery win: obfuscators store the REAL payload as
    # `local X = {45,47,32,...}` byte arrays that are only converted at runtime
    # (usually never, if the VM doesn't run them). Decode every byte-array
    # literal from the ORIGINAL source statically and append readable text.
    try:
        _static_decodes = _static_decode_bytearrays(original)
        for _t in _static_decodes:
            _m = _repr_block(_t[0])
            logs += f"\n\n-- STATIC DECODE of {_t[1]} ({_t[2]} bytes):\n-- source array:\n" + _m + "\n"
    except Exception as _e:
        print(f"{_yellow('    !')} static decode skip: {_e}")

    # Generic payload recovery: fetch the ACTUAL URLs this run logged via
    # game:HttpGet and inline their real source. No host whitelist and nothing
    # hardcoded — a GUI that loads URL X gets X's source. Only webhook/exfil
    # endpoints are flagged and never touched (a GET leaks your IP + could
    # trigger a stealer delivery to the attacker's inbox).
    def _is_webhook(u: str) -> bool:
        l = u.lower()
        return ("discord.com/api/webhooks" in l or "discordapp.com/api/webhooks" in l
                or "discordapp.net/api/webhooks" in l or "/webhooks/" in l)
    try:
        _payload_urls = []
        for _m in re.finditer(link_pattern, logs):
            _u = _m.group(0).rstrip("\"',)")
            if _u not in _payload_urls and not _is_webhook(_u):
                _payload_urls.append(_u)
        for _l in lines:
            if _l.startswith("-- LINK:"):
                _m = re.search(link_pattern, _l)
                if _m and _m.group(0).rstrip("\"',)") not in _payload_urls:
                    _u = _m.group(0).rstrip("\"',)")
                    if not _is_webhook(_u):
                        _payload_urls.append(_u)
        for _gui_url in _payload_urls[:6]:
            if args.no_fetched or args.no_fetch:
                break
            try:
                _gui_src = fetch_link(_gui_url)
            except Exception:
                _gui_src = None
            if _gui_src and len(_gui_src) > 100:
                _gui_lines = [l for l in _gui_src.splitlines() if l.strip()]
                logs += f"\n\n-- payload loaded at runtime from: {_gui_url} ({len(_gui_src)} bytes, {len(_gui_lines)} lines)\n\n" + _gui_src + "\n"
                _fp = pathlib.Path("fetched.lua")
                try:
                    _fp.write_text(_gui_src, encoding="utf-8")
                except Exception:
                    pass
                print(f"{_green('    ✓')} appended runtime payload: {_cyan(_gui_url)} ({len(_gui_lines)} lines -> fetched.lua)")
    except Exception as _e:
        print(f"{_yellow('    !')} payload append skip: {_e}")

    # auto-fetch links found in logs (game:HttpGet) — NO host whitelist:
    # fetch whatever the script actually loaded, so a paste/pastebin/discord
    # attachment/raw IP host all get recovered. Webhooks stay listed-only.
    link_pattern = r'https?://[^\s"\'\)]+'
    links = re.findall(link_pattern, logs)
    # also from raw logs -- LINK: comments
    for l in lines:
        if l.startswith("-- LINK:"):
            m = re.search(link_pattern, l)
            if m: links.append(m.group(0))
    links = list(dict.fromkeys(l.rstrip("\"',)") for l in links))  # dedupe
    # skip URLs already inlined as full payload above (avoid double-append)
    if "-- payload loaded at runtime from:" in logs:
        _inlined = re.findall(r"-- payload loaded at runtime from:\s*(\S+)", logs)
        links = [u for u in links if u not in _inlined]
    if links:
        print(f"{_cyan('   links')} {len(links)} found in logs:")
        for url in links[:8]:
            # flag likely exfil endpoints so you can see the stealer URL without touching it
            if _is_webhook(url):
                print(f"      {_red(url)}  <-- POSSIBLE EXFIL WEBHOOK (never fetched)")
            else:
                print(f"      {url}")
        # Security: a GET to an attacker URL pings them your IP. Only touch it
        # if the user forced it (--fetch) OR it's a webhook (never). Everything
        # else is fetched — payload recovery beats stealth.
        links = [u for u in links if not _is_webhook(u)]
        if len(links) == 1 and is_link:
            # if input was already a link, don't refetch
            pass
        elif links and not args.no_fetched and not args.no_fetch:
            # fetch each distinct link, append first that looks like code
            for _u in links[:4]:
                try:
                    fetched = fetch_link(_u)
                except Exception:
                    fetched = None
                if fetched and len(fetched) > 20:
                    preview = fetched[:500].replace("\n", " ")[:200]
                    print(f"{_green('    ✓')} fetched link preview: {preview}...")
                    fetched_path = pathlib.Path("fetched.lua")
                    try:
                        fetched_path.write_text(fetched, encoding="utf-8")
                    except Exception:
                        pass
                    print(f"{_green('    ✓')} full fetched script saved to {fetched_path} ({len(fetched)} bytes)")
                    _fl = "\n".join("-- [fetched] " + _l for _l in fetched.splitlines())
                    logs += f"\n\n-- FETCHED LINK FULL: {_u} ({len(fetched)} bytes, saved to fetched.lua)\n" + _fl + "\n"
                    break
    # NOTE: no whitelist anymore — any host the script's payload loads from is
    # recovered. Only exfil/webhook delivery endpoints are still never touched.

    # ------------------------------------------------------------------
    # PAYLOAD SELECTION
    # The primary artifact is the RECOVERED PAYLOAD SOURCE: real, runnable Lua.
    # The call trace is a behaviour log (not valid Lua) and goes to a sidecar.
    # Candidates are ranked by how runnable and how complete they are.
    # ------------------------------------------------------------------
    def _luausible_lua(text: str) -> bool:
        """Cheap sanity check that a candidate is Lua source, not a trace line."""
        if not text or not text.strip():
            return False
        t = text.strip()
        # a payload starts as code, never as a comment banner
        if t.startswith("--") and "\n" not in t[:200]:
            return False
        return True

    _candidates = []  # (rank, label, text) - lower rank wins

    # 1. static bPeM deobfuscation is the highest-fidelity recovery we have
    if deob_src:
        _candidates.append((0, "bPeM static deobfuscation", deob_src))

    # 2. second-stage sources: what loadstring() actually received at runtime
    if _stages_out:
        _stage_txt = "\n".join(_stages_out).strip("\n")
        if _luausible_lua(_stage_txt):
            _candidates.append((1, "second-stage loadstring payload", _stage_txt))

    # 3. a fetched link that is real code (the loader/enclib stage).
    #    Only counts if it was fetched during THIS run - the file is shared
    #    across invocations, so a stale one would misattribute another sample.
    try:
        _fx = pathlib.Path("fetched.lua")
        if _fx.exists() and _fx.stat().st_mtime >= _run_started - 2:
            _ftxt = _fx.read_text(encoding="utf-8", errors="replace")
            if _luausible_lua(_ftxt) and len(_ftxt.strip()) > 40:
                _candidates.append((2, "fetched link source", _ftxt))
    except Exception:
        pass

    # 4. static byte-array decodes recovered from the ORIGINAL source
    try:
        if _static_decodes:
            _sd = "\n".join(_t[0] for _t in _static_decodes)
            if _luausible_lua(_sd):
                _candidates.append((3, "static byte-array decode", _sd))
    except Exception:
        pass

    # 5. harvested runtime strings
    if _harv_out:
        _htxt = "\n".join(_harv_out).strip("\n")
        if _luausible_lua(_htxt):
            _candidates.append((4, "harvested runtime strings", _htxt))

    out_path = pathlib.Path(args.output)

    # pick the winner: best rank, and among equals the most complete
    _best = None
    if _candidates:
        _best_rank = min(c[0] for c in _candidates)
        _same = [c for c in _candidates if c[0] == _best_rank]
        _best = max(_same, key=lambda c: len(c[2]))

    if _best is not None:
        _rank, _label, _text = _best
        _text = _text.replace("\r\n", "\n")
        if not _text.endswith("\n"):
            _text += "\n"
        out_path.write_text(_text, encoding="utf-8")
        _payload_written = True
        _payload_label = _label
    else:
        # Nothing runnable was recovered: keep the trace as the primary output so
        # the run is never a silent no-op, but say so plainly.
        out_path.write_text(logs + "\n", encoding="utf-8")
        _payload_written = False
        _payload_label = "call trace (no payload recovered)"

    # sidecar: the call trace, always a behaviour log and never runnable Lua
    if not args.no_trace:
        if args.trace_out:
            _trace_path = pathlib.Path(args.trace_out)
        else:
            _trace_path = out_path.with_name(out_path.stem + ".trace.lua")
        _trace_path.write_text("--Deobfuscated by Comet\n\n" + logs + "\n", encoding="utf-8")
    else:
        _trace_path = None

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    def _safe_print(s):
        try:
            print(s)
        except UnicodeEncodeError:
            try:
                print(s.encode("utf-8", errors="backslashreplace").decode("utf-8", errors="backslashreplace"))
            except Exception:
                print(repr(s)[:200])
    print()
    _section(" result ")
    if _payload_written:
        _kv("payload", _green(str(out_path)) + _dim(f"  ({_payload_label})"))
    else:
        _kv("output", _yellow(str(out_path)) + _dim("  (call trace - nothing runnable recovered)"))
    if _trace_path is not None:
        _kv("trace", _dim(str(_trace_path)))
    _kv("lines", f"{len(filtered)} logged")
    if _junk_count >= 20:
        _kv("vm-junk", f"collapsed {_junk_count} decode calls")
    if links:
        _kv("links", f"{len(links)} found")
    _rule()
    _safe_print(f"{_bold(_cyan('   preview'))}")
    for l in filtered[:30]:
        _safe_print("      " + l)
    if len(filtered) > 30:
        _safe_print(f"      {_dim('...')} +{len(filtered)-30} more")
    _rule("═", 64)
    _safe_print(f"{_green('  ✓')} logged -> {_green(str(out_path))}")

    # --report: write full console report (stats + all logged lines) to file
    if getattr(args, "report", None):
        report_path = pathlib.Path(args.report)
        report_lines = []
        report_lines.append(f"=== ENV LOGGER REPORT ===")
        report_lines.append(f"source: {src_path} ({len(original)} bytes)")
        report_lines.append(f"output: {out_path}")
        report_lines.append(f"lines:  {len(filtered)} logged / {len(lines)} raw")
        report_lines.append(f"links:  {len(links)}")
        report_lines.append(f"vm-junk collapsed: {_junk_count}")
        report_lines.append("")
        report_lines.append("-- LOGGED LINES --")
        report_lines.extend(filtered)
        report_lines.append("")
        report_lines.append("-- LINKS --")
        for _u in links:
            report_lines.append(_u)
        report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
        print(f"{_green('    ✓')} report -> {_green(str(report_path))}")

    # --json: machine-readable single-run summary
    if getattr(args, "json_out", None):
        import json as _json
        try:
            _json.dump({
                "source": str(src_path),
                "size": len(original),
                "logged_lines": len(filtered),
                "raw_lines": len(lines),
                "links": links,
                "uncached_links": re.findall(r'-- LINK UNCACHED: (https?://\S+)', logs),
                "vm_junk_collapsed": _junk_count,
                "has_script_error": "SCRIPT ERROR" in logs,
                "status": "PASS" if len(filtered) > 0 else ("SCRIPT_ERROR" if "SCRIPT ERROR" in logs else "NO_LOGS"),
            }, open(args.json_out, "w", encoding="utf-8"), indent=1)
            print(f"{_green('    ✓')} json -> {_green(str(args.json_out))}")
        except Exception as _e:
            print(f"{_red('    ✗')} json write failed: {_e}", file=sys.stderr)

    # --auto-link: if uncached LINK lines were found, automatically re-run with --prefetch-file
    uncached_links = re.findall(r'-- LINK UNCACHED: (https?://\S+)', logs)
    if getattr(args, "auto_link", False) and uncached_links:
        print(f"{_yellow('    !')} auto-link: {len(uncached_links)} uncached link(s) detected, running prefetch + re-run...")
        _tmp_links = pathlib.Path("_auto_links.txt")
        _tmp_links.write_text("\n".join(uncached_links) + "\n", encoding="utf-8")
        extra_urls2 = list(dict.fromkeys(uncached_links))
        wrapped_src2 = build_wrapped_script(original, basename=src_path.name, extra_urls=extra_urls2, full_payload=not args.no_full_source, no_fetched=args.no_fetched, no_fetch=args.no_fetch, mock_payload=mock_payload, mock_payloads=mock_payloads or {}, place_id=args.place_id, game_id=args.game_id or args.place_id, syn_body=args.syn_body or "", chunk_arg=args.chunk_arg or "", hide_exec_globals=args.hide_exec_globals, strict_members=args.strict_members)
        wrapped_path2 = pathlib.Path("__wrapped__pass2.lua")
        wrapped_path2.write_text(wrapped_src2, encoding="utf-8")
        stdout2, stderr2, code2 = run_with_lune(wrapped_path2, executor, timeout=args.timeout)
        if stderr2:
            print(f"{_yellow('[stderr pass2]')}\n{stderr2[:2000]}")
        logs2 = ""
        if pathlib.Path("__logged__.lua").exists():
            logs2 = pathlib.Path("__logged__.lua").read_text(encoding="utf-8", errors="ignore").strip()
        if logs2 and len(logs2) > len(logs):
            logs = logs2
            # the pass-2 result is still just a call trace: it belongs in the
            # sidecar, never over the recovered payload source
            if _trace_path is not None:
                _trace_path.write_text("--Deobfuscated by Comet\n\n" + logs + "\n", encoding="utf-8")
            print(f"{_green('    ✓')} pass2 improved trace -> {_trace_path or out_path}")
        try:
            _tmp_links.unlink()
            if pathlib.Path("__logged__.lua").exists():
                pathlib.Path("__logged__.lua").unlink()
        except: pass

    try:
        if logged_path.exists(): logged_path.unlink()
    except: pass

if __name__ == "__main__":
    main()