// SSL BYPASS ONLY - No proxy configuration
// Use this if you just need to bypass SSL without HTTP Toolkit

console.log("[*] SSL-ONLY Bypass - No proxy routing");
console.log("[*] This will bypass SSL but NOT route through HTTP Toolkit");

if (ObjC.available) {
    // SSL Pinning Bypass
    console.log("[*] Installing SSL pinning bypass hooks...");
    
    // SecTrustEvaluate
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            Memory.writeU32(result, 1); // kSecTrustResultProceed
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] SecTrustEvaluate hooked");
    }
    
    // SecTrustEvaluateWithError
    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
            return 1; // true
        }, 'bool', ['pointer', 'pointer']));
        console.log("[+] SecTrustEvaluateWithError hooked");
    }
    
    // SecTrustSetAnchorCertificates
    var SecTrustSetAnchorCertificates = Module.findExportByName('Security', 'SecTrustSetAnchorCertificates');
    if (SecTrustSetAnchorCertificates) {
        Interceptor.replace(SecTrustSetAnchorCertificates, new NativeCallback(function(trust, certs) {
            return 0; // noErr
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] SecTrustSetAnchorCertificates hooked");
    }
    
    // SSLSetSessionOption
    var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
    if (SSLSetSessionOption) {
        Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
            return 0; // noErr
        }, 'int', ['pointer', 'int', 'bool']));
        console.log("[+] SSLSetSessionOption hooked");
    }
    
    // SSLHandshake
    var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
    if (SSLHandshake) {
        Interceptor.replace(SSLHandshake, new NativeCallback(function(context) {
            return 0; // noErr
        }, 'int', ['pointer']));
        console.log("[+] SSLHandshake hooked");
    }
    
    // tls_helper_create_peer_trust
    var tls_helper = Module.findExportByName('libnetwork.dylib', 'tls_helper_create_peer_trust');
    if (tls_helper) {
        Interceptor.replace(tls_helper, new NativeCallback(function() {
            return 0; // noErr
        }, 'int', []));
        console.log("[+] tls_helper_create_peer_trust hooked");
    }
    
    // nw_tls_create_peer_trust
    var nw_tls = Module.findExportByName('libnetwork.dylib', 'nw_tls_create_peer_trust');
    if (nw_tls) {
        Interceptor.replace(nw_tls, new NativeCallback(function() {
            return 0; // noErr
        }, 'int', []));
        console.log("[+] nw_tls_create_peer_trust hooked");
    }
    
    console.log("[+] SSL Pinning bypass complete!");
    console.log("[*] NO PROXY configured - traffic will NOT appear in HTTP Toolkit");
    console.log("[*] But SSL verification is bypassed - app should connect normally");
}