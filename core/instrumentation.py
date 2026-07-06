"""
Dynamic-instrumentation helpers shared across phases (Frida + objection).

Two concerns live here:

  1. Frida availability + on-device frida-server management — reused by the
     memory-dump phase (`phases/memory.py`) and the runtime-hardening phase.

  2. objection-first / raw-Frida-fallback bypass routines (Phase X) for SSL
     certificate pinning and root/debugger detection. objection is optional:
     if it is missing or fails (e.g. its known Frida-17 incompatibilities), the
     routine falls back to a self-contained Frida agent. This mirrors TrashiOS's
     tool-availability ladders (best tool first, graceful fallback).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from core.config import FRIDA_SERVER_PATH
from utils.proc import have_tool, run_tool

console = Console()


def _load_java_bridge() -> str:
    """Frida 17 removed the built-in `Java` global from raw scripts; frida-tools
    ships the compiled bridge. Prepend it (+ alias) so our Java agents work on
    Frida 16 and 17 alike. Returns "" on Frida <17 (Java is built in there)."""
    try:
        import frida_tools
        p = Path(frida_tools.__file__).parent / "bridges" / "java.js"
        if p.exists():
            return p.read_text(encoding="utf-8") + "\nvar Java = bridge;\n"
    except Exception:
        pass
    return ""


_JAVA_BRIDGE = _load_java_bridge()

# objection does a network "newer version?" check and a Frida attach on startup;
# give it room but don't let a hung REPL wedge the phase.
OBJECTION_TIMEOUT = 90
# Seconds to keep a Frida agent resident so hooks can fire during app activity.
FRIDA_OBSERVE_SECS = 6


# ── Availability + server management ─────────────────────────────

def frida_available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except ImportError:
        return False


def have_objection() -> bool:
    return have_tool("objection")


def ensure_frida_server(adb) -> bool:
    """Make sure frida-server is running on the device. Returns True if ready."""
    ps_out = adb.shell("ps -A", root=True).stdout
    if "frida-server" in ps_out:
        return True

    console.print("  [cyan]frida-server not running. Attempting to start...[/cyan]")
    exists = adb.shell(f"ls {FRIDA_SERVER_PATH}", root=True)
    if "No such file" in exists.stdout or exists.returncode != 0:
        console.print(f"  [yellow]frida-server binary not found at {FRIDA_SERVER_PATH}.[/yellow]")
        console.print("  [yellow]Download the matching frida-server from[/yellow]")
        console.print("  [yellow]  https://github.com/frida/frida/releases[/yellow]")
        console.print(f"  [yellow]  then: adb push frida-server {FRIDA_SERVER_PATH}[/yellow]")
        return False

    adb.shell(f"chmod 755 {FRIDA_SERVER_PATH}", root=True)
    adb.shell(f"{FRIDA_SERVER_PATH} -D &", root=True)
    time.sleep(2)

    if "frida-server" in adb.shell("ps -A", root=True).stdout:
        console.print("  [green]frida-server started.[/green]")
        return True

    console.print("  [yellow]frida-server failed to start.[/yellow]")
    return False


# ── Bypass result ────────────────────────────────────────────────

@dataclass
class InstrumentationResult:
    """Outcome of a bypass attempt, tool-agnostic so the phase can report uniformly."""
    tool: str = "none"           # "objection" | "frida" | "none"
    hooks_installed: bool = False  # relevant hooks/agents were placed
    bypass_observed: bool = False  # the control was actually exercised & bypassed
    evidence: str = ""
    error: str = ""


# ── Embedded Frida agents (Java) ─────────────────────────────────
# Each hook site sends "HOOK <name>" when installed and "BYPASS <name>" when the
# control is actually triggered, so the caller can distinguish "instrumented" from
# "control present and defeated".

_SSL_UNPIN_JS = r"""
'use strict';
Java.perform(function () {
    // 1. SSLContext -> permissive TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TM = Java.registerClass({
            name: 'com.trashdroid.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var tms = [TM.$new()];
        var init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        init.implementation = function (km, tm, sr) {
            send('BYPASS SSLContext.init (installed trust-all manager)');
            init.call(this, km, tms, sr);
        };
        send('HOOK SSLContext.init');
    } catch (e) { send('skip SSLContext: ' + e); }

    // 2. OkHttp3 CertificatePinner.check
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overloads.forEach(function (ov) {
            ov.implementation = function () { send('BYPASS okhttp3.CertificatePinner.check'); return; };
        });
        send('HOOK okhttp3.CertificatePinner');
    } catch (e) { /* okhttp not present */ }

    // 3. Conscrypt TrustManagerImpl (Android 7+ default)
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        try {
            TMI.verifyChain.implementation = function (chain, anchors, host, clientAuth, ocsp, sct) {
                send('BYPASS TrustManagerImpl.verifyChain host=' + host);
                return chain;
            };
        } catch (e) {}
        try {
            TMI.checkTrustedRecursive.implementation = function () {
                send('BYPASS TrustManagerImpl.checkTrustedRecursive');
                return Java.use('java.util.ArrayList').$new();
            };
        } catch (e) {}
        send('HOOK TrustManagerImpl');
    } catch (e) { /* not conscrypt */ }

    // 4. X509TrustManagerExtensions
    try {
        var TME = Java.use('android.net.http.X509TrustManagerExtensions');
        TME.checkServerTrusted.implementation = function (chain, authType, host) {
            send('BYPASS X509TrustManagerExtensions.checkServerTrusted host=' + host);
            return Java.use('java.util.ArrayList').$new();
        };
        send('HOOK X509TrustManagerExtensions');
    } catch (e) { /* not present */ }

    send('DONE ssl-unpin');
});
"""

_ROOT_BYPASS_JS = r"""
'use strict';
Java.perform(function () {
    // Path-aware root markers. NOTE: a bare "su" substring is too broad — it
    // matches innocent paths like ".../gms.measurement.prefs.xml" — so match the
    // su binary only as a path basename ("/su") or exact token.
    var rootPaths = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
                     '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
                     'superuser.apk', 'busybox', 'magisk', 'daemonsu'];
    function looksRootish(s) {
        if (!s) return false;
        s = ('' + s).toLowerCase();
        if (s === 'su' || s.slice(-3) === '/su') return true;
        if (s.indexOf('which su') !== -1) return true;
        for (var i = 0; i < rootPaths.length; i++) { if (s.indexOf(rootPaths[i]) !== -1) return true; }
        return false;
    }

    // File.exists on su/magisk paths
    try {
        var JFile = Java.use('java.io.File');
        JFile.exists.implementation = function () {
            var p = this.getAbsolutePath();
            if (looksRootish(p)) { send('BYPASS File.exists ' + p); return false; }
            return this.exists();
        };
        send('HOOK File.exists');
    } catch (e) { send('skip File: ' + e); }

    // Runtime.exec("su" / "which su")
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var execS = Runtime.exec.overload('java.lang.String');
        execS.implementation = function (cmd) {
            if (looksRootish(cmd)) { send('BYPASS Runtime.exec ' + cmd); return execS.call(this, 'true'); }
            return execS.call(this, cmd);
        };
        send('HOOK Runtime.exec');
    } catch (e) { send('skip Runtime: ' + e); }

    // RootBeer, if bundled
    try {
        var RB = Java.use('com.scottyab.rootbeer.RootBeer');
        RB.isRooted.overloads.forEach(function (ov) {
            ov.implementation = function () { send('BYPASS RootBeer.isRooted'); return false; };
        });
        send('HOOK RootBeer.isRooted');
    } catch (e) { /* not present */ }

    // Debug.isDebuggerConnected
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            send('BYPASS Debug.isDebuggerConnected'); return false;
        };
        send('HOOK Debug.isDebuggerConnected');
    } catch (e) { /* ignore */ }

    send('DONE root-bypass');
});
"""


# ── objection path ───────────────────────────────────────────────

_OBJECTION_HOOK_KEYWORDS = ("found ", "overriding", "hooking", "pinning", "job:", "trustmanager", "registering")
_OBJECTION_BYPASS_KEYWORDS = ("disabled", "bypass", "defeated")


def _objection_command(pkg: str, command: str) -> InstrumentationResult:
    """Run one objection command non-interactively against a running app."""
    if not have_objection():
        return InstrumentationResult(tool="none", error="objection not installed")

    # `--startup-command` installs the hook immediately; feeding "exit" on stdin
    # leaves the REPL so the process terminates instead of hanging.
    res = run_tool(
        ["objection", "-g", pkg, "explore", "--startup-command", command],
        timeout=OBJECTION_TIMEOUT,
        input_text="exit\n",
    )
    out = res.combined
    low = out.lower()
    if not res.found:
        return InstrumentationResult(tool="none", error="objection not installed")
    hooks = any(k in low for k in _OBJECTION_HOOK_KEYWORDS)
    bypass = any(k in low for k in _OBJECTION_BYPASS_KEYWORDS)
    return InstrumentationResult(tool="objection", hooks_installed=hooks,
                                 bypass_observed=bypass, evidence=out[:4000])


# ── frida path ───────────────────────────────────────────────────

def _frida_run(pkg: str, script_js: str, observe_secs: int = FRIDA_OBSERVE_SECS) -> InstrumentationResult:
    """Spawn the app, load a Frida agent, and collect its messages for a window."""
    try:
        import frida
    except ImportError:
        return InstrumentationResult(tool="none", error="frida python bindings not installed")

    messages: list[str] = []
    session = None
    pid = None
    try:
        device = frida.get_usb_device(timeout=10)
        pid = device.spawn([pkg])
        session = device.attach(pid)
        # Prepend the Java bridge so `Java.perform` resolves on Frida 17 (which
        # dropped the built-in Java global); no-op string on Frida <17.
        script = session.create_script(_JAVA_BRIDGE + script_js)

        def on_message(message, data):
            if message.get("type") == "send":
                messages.append(str(message.get("payload")))
            elif message.get("type") == "error":
                messages.append("ERROR: " + str(message.get("stack") or message.get("description")))

        script.on("message", on_message)
        script.load()
        device.resume(pid)
        time.sleep(observe_secs)
    except Exception as e:  # frida surfaces many transport/attach errors as plain Exception
        return InstrumentationResult(tool="frida", evidence="\n".join(messages)[:4000],
                                     error=f"frida error: {e}")
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    hooks = any(m.startswith("HOOK") for m in messages)
    bypass = any(m.startswith("BYPASS") for m in messages)
    return InstrumentationResult(tool="frida", hooks_installed=hooks,
                                 bypass_observed=bypass, evidence="\n".join(messages)[:4000])


# ── public bypass entry points (objection → frida) ───────────────

def _bypass(adb, pkg: str, objection_command: str, frida_script: str) -> InstrumentationResult:
    # 1. objection first — richer built-in coverage when it works.
    if have_objection():
        result = _objection_command(pkg, objection_command)
        if result.hooks_installed:
            return result
    else:
        result = InstrumentationResult(tool="none", error="objection not installed")

    # 2. Fall back to a self-contained Frida agent.
    if frida_available() and ensure_frida_server(adb):
        frida_result = _frida_run(pkg, frida_script)
        if frida_result.hooks_installed or not have_objection():
            return frida_result
        # objection ran but installed nothing and frida also found nothing: prefer
        # whichever produced evidence.
        return frida_result if frida_result.evidence else result

    return result


def disable_ssl_pinning(adb, pkg: str) -> InstrumentationResult:
    """Attempt to defeat SSL certificate pinning (objection → Frida)."""
    return _bypass(adb, pkg, "android sslpinning disable", _SSL_UNPIN_JS)


def disable_root_detection(adb, pkg: str) -> InstrumentationResult:
    """Attempt to defeat root/debugger detection (objection → Frida)."""
    return _bypass(adb, pkg, "android root disable", _ROOT_BYPASS_JS)
