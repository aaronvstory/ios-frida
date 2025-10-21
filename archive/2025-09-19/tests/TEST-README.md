# FridaInterceptor Ultimate Test Suite

Comprehensive automated validation for the FridaInterceptor Ultimate system.

## Overview

This test suite validates all components of the FridaInterceptor system:
- File structure and configurations
- Script content and syntax  
- SSH tunnel connectivity
- Frida tools availability
- Device connectivity
- App configurations
- Python helper scripts
- Integration workflows
- Security settings
- Dependencies

## Quick Start

### Windows Batch Launcher
```batch
# Run full test suite
test.bat

# Quick validation (skip device tests)
test.bat -quick

# Detailed output
test.bat -verbose
```

### PowerShell Direct
```powershell
# Full test suite
.\test-frida-interceptor.ps1

# Quick mode (skip interactive tests)
.\test-frida-interceptor.ps1 -Quick

# Verbose output with details
.\test-frida-interceptor.ps1 -Verbose

# Test specific device
.\test-frida-interceptor.ps1 -Device "your-device-id"

# Disable colors for logging
.\test-frida-interceptor.ps1 -NoColor
```

## Test Categories

### 1. File Structure Validation ✅
- Verifies all required files exist
- Checks for proper file permissions
- Validates file sizes and accessibility

### 2. Configuration Validation ✅  
- JSON syntax validation
- Required fields verification
- App configuration validation
- Mode settings (spawn/attach) verification

### 3. Script Content Validation ✅
- JavaScript syntax checking
- Key functionality presence verification
- HTTP/HTTPS interception capabilities
- Certificate pinning bypass features
- Error handling implementation

### 4. Python Helper Scripts ✅
- Syntax validation using py_compile
- Import dependency checking
- Required functionality verification
- Cross-platform compatibility

### 5. SSH and Device Connectivity ⚡
- Network connectivity testing
- SSH tunnel establishment
- Device accessibility verification
- Port availability checking

### 6. Frida Tools Availability ✅
- frida-ps command testing
- frida core command testing  
- Version compatibility checking
- Device enumeration testing

### 7. App Configuration Testing ✅
- Bundle identifier validation
- Mode configuration verification
- Custom script path checking
- Device app availability (when connected)

### 8. Proxy Script Functionality ✅
- Python import testing
- Configuration integration
- Functionality availability
- Error handling validation

### 9. Integration Testing 🔄
- End-to-end workflow simulation
- Component interaction testing
- Configuration loading verification
- Script execution preparation

### 10. Smoke Test 🚀
- Complete workflow simulation
- All components ready verification
- Quick health check
- Critical path validation

### 11. Security and Permissions 🔒
- Administrator privileges checking
- Credential security validation
- Network binding verification
- Security configuration review

### 12. Environment and Dependencies 📦
- Python availability and version
- Required package installation
- USB debugging tools
- System compatibility

## Test Results

### Success Indicators
- ✅ **Green checkmarks**: Tests passed
- ⚠️ **Yellow warnings**: Tests skipped (with reason)
- ❌ **Red X marks**: Tests failed

### Result Metrics
- **Passed**: Number of successful tests
- **Failed**: Number of failed tests  
- **Skipped**: Number of skipped tests
- **Success Rate**: Percentage of passed tests

### Exit Codes
- `0`: All tests passed
- `1`: One or more tests failed

## Common Issues and Solutions

### Configuration Issues
```
✗ Config file parsing
```
**Solution**: Verify JSON syntax in `config.json`

### Frida Not Available
```
✗ frida-ps command available
```
**Solution**: Install Frida tools
```bash
pip install frida-tools
```

### Device Connectivity Issues
```
✗ Device network connectivity
```
**Solution**: 
1. Check device IP and port in config
2. Ensure device is on same network
3. Verify SSH access is enabled

### Python Package Issues
```
✗ Python package: frida
```
**Solution**: Install required packages
```bash
pip install frida frida-tools
```

## Advanced Usage

### Custom Device Testing
```powershell
# Test specific device by ID
.\test-frida-interceptor.ps1 -Device "iPhone-12-Pro"

# Get device list first
frida-ls-devices
```

### Automated CI/CD Integration
```bash
# In CI/CD pipeline
powershell -ExecutionPolicy Bypass -File test-frida-interceptor.ps1 -Quick -NoColor
if ($LASTEXITCODE -ne 0) { exit 1 }
```

### Logging and Reports
```powershell
# Capture detailed logs
.\test-frida-interceptor.ps1 -Verbose > test-results.log 2>&1

# Parse results programmatically  
if ($LASTEXITCODE -eq 0) { 
    Write-Host "All systems operational" 
}
```

## Troubleshooting

### Test Script Execution Issues
1. **Execution Policy**: Run as Administrator and set execution policy
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

2. **Path Issues**: Run from the correct directory containing all files

3. **Permission Issues**: Ensure you have read access to all test files

### Device Connection Problems  
1. Check network connectivity to device
2. Verify SSH keys are properly configured
3. Ensure frida-server is running on device
4. Test basic frida-ps connection manually

### Python Environment Issues
1. Verify Python is in PATH
2. Check virtual environment activation
3. Install missing packages
4. Verify Python version compatibility (3.7+)

## Integration with FridaInterceptor

This test suite is designed to work with:
- `frida-interceptor-ultimate.js` - Main interception script
- `config.json` - System configuration  
- `frida_ios_proxy.py` - Proxy helper script
- `setup_proxy.py` - Configuration setup script

Make sure all components are present before running tests.

## Contributing

When adding new tests:
1. Follow existing test patterns
2. Use `Test-Result` function for consistent output
3. Add appropriate error handling
4. Update this README with new test descriptions
5. Consider both quick and full test modes

## Support

For issues with the test suite:
1. Run with `-Verbose` flag for detailed output
2. Check individual test failures
3. Verify all prerequisites are installed
4. Test components individually before full suite