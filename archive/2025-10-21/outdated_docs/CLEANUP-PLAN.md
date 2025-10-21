# Workspace Cleanup Plan

## Files to Archive (Move to `archive/`)

### Old Launchers → `archive/old-launchers/`
These are redundant now that we have `FRIDA-LIVE-MONITOR.bat`:

- CAPTURE-NOW.bat
- DASHER-FIX-NOW.bat
- monitor-dasher-live.bat
- MONITOR-NOW.bat
- quick-dasher-fix.bat
- RUN-403-FIX.bat
- RUN-ACCOUNT-REACTIVATOR.bat
- RUN-DASHER-INFO-ADVANCED.bat
- RUN-DASHER-INFO.bat
- RUN-JAILBREAK-BYPASS.bat
- RUN-JB-BYPASS-FIXED.bat
- RUN-MONITOR.bat
- RUN-PERFECT-BYPASS.bat
- RUN-SAFE-BYPASS.bat
- RUN-ULTIMATE-BYPASS.bat
- RUN-ULTIMATE-DASH.bat
- RUN-ULTIMATE-MONITOR.bat
- SPAWN-CAPTURE.bat
- start-frida-interceptor.bat
- test-analytics-spoof.bat
- test-api-error-fix.bat
- test-comprehensive-spoof.bat
- test-reset-with-termination.bat
- test-spoof-comparison.bat

### Old Scripts → `archive/old-scripts/`
Superseded by `live-network-monitor.py`:

- autonomous-fix.py
- direct-analytics-fix.py
- direct-monitor.py
- enhanced-live-monitor.py
- final-functional-test.py
- network-capture-monitor.py
- simple-monitor.py
- spawn-monitor.py
- test-dasher-connection.py

Root JS files (moved to frida-interception-and-unpinning/):
- account-reactivator.js
- dasher-info-advanced.js
- dasher-info-extractor.js
- fix-403-error.js
- force-dash-button.js
- jailbreak-bypass-fixed.js
- jailbreak-bypass.js
- minimal-safe-bypass.js
- perfect-bypass.js
- save-dasher-log.js
- ultimate-403-bypass.js
- ultimate-dash-enabler.js
- ultimate-monitor.js

### Old Documentation → `archive/old-docs/`
Superseded by `LIVE-MANIPULATION-GUIDE.md`:

- ANALYTICS-FIX-SOLUTION.md
- API-ERROR-FIX-SOLUTION.md
- AUTONOMOUS-FIX-GUIDE.md
- BUGS-FIXED-COMPLETE.md
- BUGS-FIXED.md
- COMPREHENSIVE-SPOOFING-GUIDE.md
- CTRL-C-HANDLER-ADDED.md
- DASHER-FIX-NOW.md
- DASHER-ONLY-FIX.md
- DOORDASH-NETWORK-ERROR-FIX.md
- DOORDASH-ONLY-FIX-COMPLETE.md
- DOORDASH-ONLY-FIXED.md
- DOORDASH-TYPEERROR-FIXED.md
- ENHANCED-RESET-FUNCTIONALITY.md
- FINAL-FIX-COMPLETE.md
- FINAL-SUMMARY.md
- LIGHTWEIGHT-MODE-ADDED.md
- MINIMAL-SAFE-BYPASS.md
- NSURLSESSION-HOOK-FAILURE-FIXED.md
- PID-ERROR-FIXED.md
- README-DASHER-FIX.md
- REDIRECT-ERROR-FIXED.md
- RESET-COMPLETE-WITH-TERMINATION.md
- RESET-SCRIPT-OVERRIDE-FIXED.md
- SSL-ERROR-FIXED.md
- TEST-COMPLETE.md

### Old PowerShell Scripts → `archive/old-launchers/`
Redundant test scripts:

- FridaDasherLauncher.ps1
- FridaInterceptor.ps1
- test-ctrl-c-handler.ps1
- test-doordash-fix.ps1
- test-doordash-only-fix.ps1
- test-enhanced-reset.ps1
- test-reset.ps1
- validate-doordash-fix.ps1
- validate-reset-script.ps1
- verify-installation.ps1
- verify-reset-fix.ps1

## Files to Keep in Root

### Core Files (Essential)
- ✅ **FRIDA-LIVE-MONITOR.bat** - Main launcher
- ✅ **live-network-monitor.py** - Advanced monitor
- ✅ **frida-spawn.py** - Core spawn functionality
- ✅ **frida-attach.py** - Core attach functionality
- ✅ **LIVE-MANIPULATION-GUIDE.md** - Main documentation
- ✅ **CLAUDE.md** - Project overview
- ✅ **README.md** - Quick start guide
- ✅ **QUICK-START.md** - User guide
- ✅ **requirements.txt** - Python dependencies
- ✅ **plink.exe** - SSH tunnel utility

### Configuration
- ✅ `config/frida-config.json`

### Working Scripts
- ✅ `frida-interception-and-unpinning/` directory (all JS files)

### Logs
- ✅ `logs/` directory (keep for current logs)
- Archive old logs older than 7 days

## Clean Root Directory Structure

After cleanup, root should contain:

```
C:\claude\ios frida\
├── FRIDA-LIVE-MONITOR.bat          ← MAIN LAUNCHER
├── live-network-monitor.py          ← Advanced monitor
├── frida-spawn.py                   ← Core
├── frida-attach.py                  ← Core
├── plink.exe                        ← SSH tunnel
├── requirements.txt                 ← Dependencies
│
├── LIVE-MANIPULATION-GUIDE.md       ← MAIN DOCS
├── CLAUDE.md                        ← Project overview
├── README.md                        ← Quick start
├── QUICK-START.md                   ← User guide
│
├── config/                          ← Configuration
│   └── frida-config.json
│
├── frida-interception-and-unpinning/ ← All JS scripts
│   ├── enhanced-universal-ssl-pinning-bypass-with-proxy-fixed.js
│   ├── attach-mode-proxy.js
│   └── ... (other working scripts)
│
├── logs/                            ← Current logs
│   └── ... (recent logs)
│
├── archive/                         ← Old files
│   ├── old-launchers/
│   ├── old-scripts/
│   └── old-docs/
│
└── .claude/                         ← Claude Code config
```

## How to Execute Cleanup

Run this command:
```bash
# Move files to archive
# (Will be done automatically)
```

## Benefits After Cleanup

1. ✅ **Clear entry point** - One main launcher: `FRIDA-LIVE-MONITOR.bat`
2. ✅ **Organized structure** - Easy to find files
3. ✅ **Preserved history** - Old files in `archive/` if needed
4. ✅ **Better navigation** - No more clutter
5. ✅ **Up-to-date docs** - Single source of truth

## Rollback Plan

If you need an old file:
1. Check `archive/old-launchers/`, `archive/old-scripts/`, or `archive/old-docs/`
2. Copy back to root if needed
3. All functionality is preserved in new unified scripts
