// Enhanced SSL Pinning Bypass with Proxy Routing - FIXED VERSION
// Handles binary data gracefully and improves attach mode compatibility

console.log("[*] Starting Enhanced Universal SSL Pinning Bypass with Proxy (Fixed)...");

// Proxy configuration
var proxyHost = "192.168.50.9";
var proxyPort = 8000;

console.log("[*] Target proxy: " + proxyHost + ":" + proxyPort);

var requestCount = 0;

// Safe string reading helper
function safeReadString(ptr) {
    try {
        if (ptr && !ptr.isNull()) {
            return Memory.readUtf8String(ptr);
        }
    } catch (e) {
        // Binary data or invalid pointer - ignore
    }
    return null;
}

// Objective-C runtime hooks
if (ObjC.available) {
    try {
        console.log("[*] Objective-C runtime available, installing hooks...");
        
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        
        function configureProxyForConfig(config, configType) {
            try {
                console.log("[*] Configuring proxy for " + configType);
                
                var proxyDict = ObjC.classes.NSMutableDictionary.alloc().init();
                
                // Comprehensive proxy settings
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPPort");
                
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(1), "HTTPSEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSString.stringWithString_(proxyHost), "HTTPSProxy");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(proxyPort), "HTTPSPort");
                
                // Disable proxy auto-config
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(0), "ProxyAutoConfigEnable");
                proxyDict.setObject_forKey_(ObjC.classes.NSNumber.numberWithInt_(0), "ProxyAutoDiscoveryEnable");
                
                config.setConnectionProxyDictionary_(proxyDict);
                console.log("[+] Proxy configured: " + proxyHost + ":" + proxyPort);
            } catch (e) {
                console.log("[!] Error configuring proxy: " + e);
            }
        }
        
        // Hook all NSURLSessionConfiguration methods
        ['+ defaultSessionConfiguration', '+ ephemeralSessionConfiguration', '+ backgroundSessionConfiguration:'].forEach(function(method) {
            try {
                var origMethod = NSURLSessionConfiguration[method];
                if (origMethod) {
                    Interceptor.attach(origMethod.implementation, {
                        onLeave: function(retval) {
                            var config = new ObjC.Object(retval);
                            configureProxyForConfig(config, method.replace('+ ', ''));
                        }
                    });
                }
            } catch (e) {
                // Method might not exist in this iOS version
            }
        });
        
        // Hook NSURLSession creation methods
        if (ObjC.classes.NSURLSession) {
            ['+ sessionWithConfiguration:', '+ sessionWithConfiguration:delegate:delegateQueue:'].forEach(function(method) {
                try {
                    var origMethod = ObjC.classes.NSURLSession[method];
                    if (origMethod) {
                        Interceptor.attach(origMethod.implementation, {
                            onEnter: function(args) {
                                var config = new ObjC.Object(args[2]);
                                configureProxyForConfig(config, method.replace('+ ', ''));
                            }
                        });
                    }
                } catch (e) {
                    // Method might not exist
                }
            });
        }
        
        // Hook NSURLRequest creation with safe string reading
        if (ObjC.classes.NSURLRequest) {
            ['+ requestWithURL:', '- initWithURL:'].forEach(function(method) {
                try {
                    var origMethod = ObjC.classes.NSURLRequest[method];
                    if (origMethod) {
                        Interceptor.attach(origMethod.implementation, {
                            onEnter: function(args) {
                                try {
                                    var url = new ObjC.Object(args[2]);
                                    if (url && url.absoluteString) {
                                        requestCount++;
                                        console.log("[" + requestCount + "] NSURLRequest: " + url.absoluteString());
                                    }
                                } catch (e) {
                                    // Ignore errors
                                }
                            }
                        });
                    }
                } catch (e) {
                    // Method might not exist
                }
            });
        }

        // SSL Pinning Bypass
        console.log("[*] Installing SSL pinning bypass hooks...");
        
        // SecTrustEvaluate hooks
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                Memory.writeU32(result, 1); // kSecTrustResultProceed
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
        }
        
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
                return 1; // true - evaluation successful
            }, 'bool', ['pointer', 'pointer']));
        }
        
        // SSLSetSessionOption bypass
        var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
                return 0; // noErr
            }, 'int', ['pointer', 'int', 'bool']));
        }
        
        // SSLCreateContext bypass
        var SSLCreateContext = Module.findExportByName('Security', 'SSLCreateContext');
        if (SSLCreateContext) {
            Interceptor.attach(SSLCreateContext, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
                        if (SSLSetSessionOption) {
                            var fn = new NativeFunction(SSLSetSessionOption, 'int', ['pointer', 'int', 'bool']);
                            fn(retval, 4, 1); // kSSLSessionOptionBreakOnServerAuth
                        }
                    }
                }
            });
        }
        
        console.log("[+] SSL Pinning bypass hooks installed");
        console.log("[+] Proxy routing configured");
        console.log("[+] Ready to intercept ALL traffic!");
        
    } catch (error) {
        console.log("[!] Error during setup: " + error);
    }
}

// CFNetwork hooks with safe handling
if (Module.findExportByName('CFNetwork', 'CFHTTPMessageCreateRequest')) {
    try {
        Interceptor.attach(Module.findExportByName('CFNetwork', 'CFHTTPMessageCreateRequest'), {
            onEnter: function(args) {
                try {
                    var method = safeReadString(args[1]);
                    var url = safeReadString(args[2]);
                    if (method && url) {
                        requestCount++;
                        console.log("[" + requestCount + "] CFNetwork: " + method + " " + url);
                    }
                } catch (e) {
                    // Ignore decode errors
                }
            }
        });
    } catch (e) {
        console.log("[!] CFNetwork hook failed: " + e);
    }
}

console.log("[*] Script fully loaded - monitoring traffic...");

// Periodic status update
setInterval(function() {
    if (requestCount > 0) {
        console.log("[*] Total requests intercepted: " + requestCount);
    }
}, 30000); // Every 30 seconds