# 📱 iOS Frida Workspace - Clean Organization

## 🚀 Quick Start
```batch
# Main launcher - just run this!
start-ultimate.bat
```

## 📂 Directory Structure

```
C:\claude\ios frida\
│
├── 🎯 CORE FILES (Root)
│   ├── start-ultimate.bat          # Main launcher
│   ├── FridaInterceptor-Ultimate.ps1  # Core script
│   ├── frida-spawn.py             # Python helper (spawn mode)
│   ├── frida-attach.py            # Python helper (attach mode)
│   ├── requirements.txt           # Python dependencies
│   └── CLAUDE.md                  # AI assistant guide
│
├── 📁 /frida-interception-and-unpinning/  # Frida JS scripts
│   ├── enhanced-*-proxy-fixed.js  # Best script (no errors)
│   ├── attach-mode-proxy.js       # For attach mode
│   └── universal-ssl-*.js         # Various SSL bypass scripts
│
├── 📁 /config/                    # Configuration
│   ├── frida-config.json         # Network & app settings
│   └── frida-config.json.backup  # Backup config
│
├── 📁 /tests/                     # Testing & Diagnostics
│   ├── test-frida-interceptor.ps1  # Full test suite
│   ├── diagnose-proxy-issue.ps1   # Proxy troubleshooting
│   ├── test-both-modes.bat       # Test spawn vs attach
│   └── test.bat                  # Quick test launcher
│
├── 📁 /launchers/                 # Alternative Launchers
│   ├── run-enhanced.bat          # Force enhanced proxy mode
│   ├── quick-fix-proxy.bat       # Quick proxy fix
│   ├── attach-doordash-enhanced.bat  # Direct DoorDash attach
│   └── setup-frida.bat           # Initial setup
│
├── 📁 /docs/                      # Documentation
│   ├── SOLUTION-HTTP-TOOLKIT.md  # HTTP Toolkit solutions
│   ├── fix-http-toolkit-visibility.ps1  # Visibility fix script
│   └── *.md                      # Various guides
│
├── 📁 /logs/                      # Runtime logs
│   └── (Auto-generated log files)
│
└── 📁 /archive/                   # Old/Backup files
    └── 2024-12-*/                # Organized by date
```

## 🎮 Common Workflows

### Standard Usage
```batch
# 1. Start the interceptor
start-ultimate.bat

# 2. Choose mode:
#    Option 2: Spawn (reliable, logs you out)
#    Option 5: Attach (stay logged in, less reliable)
```

### Testing & Troubleshooting
```batch
# Run full test suite
tests\test-frida-interceptor.ps1

# Diagnose proxy issues
tests\diagnose-proxy-issue.ps1

# Test both modes
tests\test-both-modes.bat
```

### Quick Fixes
```batch
# Force enhanced proxy mode
launchers\run-enhanced.bat

# Quick proxy fix
launchers\quick-fix-proxy.bat
```

## 🔧 Key Configuration

**Network Settings** (`config/frida-config.json`):
- iPhone IP: 192.168.50.113
- HTTP Toolkit: 192.168.50.9:8000
- SSH Tunnel: localhost:27042

**Supported Apps**:
- DoorDash Customer: `doordash.DoorDashConsumer`
- DoorDash Dasher: `com.doordash.dasher`
- Safari: `com.apple.mobilesafari`

## 📊 Current Status

✅ **Working**: Spawn mode (Option 2) - Traffic appears in HTTP Toolkit
⚠️ **Experimental**: Attach mode (Option 5) - Inconsistent proxy routing

## 🎯 Recommended Workflow

1. **For reliable interception**: Use spawn mode (Option 2)
2. **Accept**: App will restart and log you out
3. **Result**: All traffic appears in HTTP Toolkit

## 📝 Notes

- The workspace has been cleaned and organized for clarity
- All core functionality remains unchanged
- Test files are now in `/tests` for better organization
- Alternative launchers in `/launchers` if needed
- Documentation consolidated in `/docs`

Last cleaned: December 2024