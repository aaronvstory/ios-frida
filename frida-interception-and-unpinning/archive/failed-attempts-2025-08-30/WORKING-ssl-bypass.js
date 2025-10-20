// WORKING SSL Bypass - Minimal, reliable, no DNS issues
console.log("[*] Starting WORKING SSL Bypass...");

if (ObjC.available) {
    setTimeout(function() {
        console.log("[*] Installing SSL bypass hooks...");
        
        // 1. SecTrustEvaluate - Main SSL verification
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                Memory.writeU32(result, 1); // kSecTrustResultProceed  
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluate bypassed");
        }
        
        // 2. SecTrustEvaluateWithError - iOS 12+
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                return 1; // true
            }, 'bool', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluateWithError bypassed");
        }
        
        // 3. SSLSetSessionOption
        var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
                return 0; // noErr
            }, 'int', ['pointer', 'int', 'bool']));
            console.log("[+] SSLSetSessionOption bypassed");
        }
        
        // 4. SSLHandshake
        var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
        if (SSLHandshake) {
            Interceptor.replace(SSLHandshake, new NativeCallback(function(context) {
                return 0; // noErr
            }, 'int', ['pointer']));
            console.log("[+] SSLHandshake bypassed");
        }
        
        // 5. Network framework hooks
        var tls_helper = Module.findExportByName('libnetwork.dylib', 'tls_helper_create_peer_trust');
        if (tls_helper) {
            Interceptor.replace(tls_helper, new NativeCallback(function() {
                return 0; // noErr
            }, 'int', []));
            console.log("[+] tls_helper_create_peer_trust bypassed");
        }
        
        // 6. nw_tls_create_peer_trust
        var nw_tls = Module.findExportByName('libnetwork.dylib', 'nw_tls_create_peer_trust');
        if (nw_tls) {
            Interceptor.replace(nw_tls, new NativeCallback(function() {
                return 0; // noErr
            }, 'int', []));
            console.log("[+] nw_tls_create_peer_trust bypassed");
        }
        
        console.log("[+] SSL Bypass complete!");
        console.log("[*] App should connect without certificate errors");
        
    }, 100); // Small delay to ensure app is ready
}