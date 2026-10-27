'use strict';

const FAKE_PID = '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<PidData>\n' +
  '  <Resp errCode="0" errInfo="Capture successful"/>\n' +
  '  <DeviceInfo dpId="MOCK" rdsId="MOCK" rdsVer="1.0" dc="MOCK" mi="MOCK" mc="MOCK"/>\n' +
  '  <Skey ci="20260101">MOCK</Skey>\n' +
  '  <Hmac>MOCK</Hmac>\n' +
  '  <Data type="X">MOCK</Data>\n' +
  '</PidData>';

function log(message) {
  try { console.log(message); } catch (_) {}
}

function hook(label, fn) {
  try {
    fn();
    log('[+] ' + label);
  } catch (e) {
    log('[-] ' + label + ': ' + e);
  }
}

Java.perform(function () {
  hook('MaaS360 gate', function () {
    const Gate = Java.use('com.equitas.face.rd.MaaS360Gate');
    Gate.isBlocked.implementation = function () { return false; };
    try {
      Gate.block.overload('java.lang.String', 'java.lang.String').implementation = function (code, message) {
        log('[+] Suppressed MaaS360 block: ' + code + ' ' + message);
      };
    } catch (_) {}
  });

  hook('FaceRD security checks', function () {
    const Main = Java.use('com.equitas.face.rd.MainActivity');
    Main.isDeviceRooted.implementation = function () {
      log('[+] isDeviceRooted -> false');
      return false;
    };
    Main.isUsbDebuggingEnabled.implementation = function () {
      log('[+] isUsbDebuggingEnabled -> false');
      return false;
    };
    Main.isDeveloperModeEnabled.implementation = function () {
      log('[+] isDeveloperModeEnabled -> false');
      return false;
    };
    Main.isPackageInstalled.implementation = function (pkg) {
      log('[+] isPackageInstalled(' + pkg + ') -> true');
      return true;
    };
    Main.getAppVersion.implementation = function (pkg) {
      return '1.0.25';
    };
    Main.checkAppPermission.implementation = function (pkg, permission) {
      log('[+] checkAppPermission(' + pkg + ', ' + permission + ') -> true');
      return true;
    };
  });

  hook('FaceRD configuration logging', function () {
    const Main = Java.use('com.equitas.face.rd.MainActivity');
    const init = Main.initializeConfiguration;
    init.implementation = function (config) {
      log('[*] FaceRD config: ' + config);
      return init.call(this, config);
    };
  });

  hook('Face capture bypass', function () {
    const Main = Java.use('com.equitas.face.rd.MainActivity');
    const handleCaptureResult = Main.handleCaptureResult.overload(
      'android.content.Intent',
      'java.lang.String',
      'java.lang.String'
    );
    const handleFaceCapture = Main.handleFaceCapture;
    handleFaceCapture.implementation = function (args, result) {
      log('[+] Bypassing external FaceRD face capture');
      const Intent = Java.use('android.content.Intent');
      const HashMap = Java.use('java.util.HashMap');
      const BooleanClass = Java.use('java.lang.Boolean');
      const fakeIntent = Intent.$new();
      fakeIntent.putExtra('PID_DATA', FAKE_PID);
      const launched = HashMap.$new();
      launched.put('launched', BooleanClass.TRUE);
      try { result.success(launched); } catch (e) { log('[-] result.success: ' + e); }
      const self = this;
      const callback = String(this.onFaceCapturedMethod.value || 'onFaceCaptured');
      setTimeout(function () {
        try {
          Java.scheduleOnMainThread(function () {
            try {
              handleCaptureResult.call(self, fakeIntent, callback, 'Face');
              log('[+] Injected onFaceCaptured success');
            } catch (e) {
              log('[-] handleCaptureResult: ' + e);
            }
          });
        } catch (e) {
          log('[-] scheduleOnMainThread: ' + e);
        }
      }, 300);
    };
  });

  hook('Biometric capture bypass', function () {
    const Main = Java.use('com.equitas.face.rd.MainActivity');
    const handleCaptureResult = Main.handleCaptureResult.overload(
      'android.content.Intent',
      'java.lang.String',
      'java.lang.String'
    );
    const handleBiometricCapture = Main.handleBiometricCapture;
    handleBiometricCapture.implementation = function (args, result) {
      log('[+] Bypassing external biometric capture');
      const Intent = Java.use('android.content.Intent');
      const HashMap = Java.use('java.util.HashMap');
      const BooleanClass = Java.use('java.lang.Boolean');
      const fakeIntent = Intent.$new();
      fakeIntent.putExtra('PID_DATA', FAKE_PID);
      const launched = HashMap.$new();
      launched.put('launched', BooleanClass.TRUE);
      try { result.success(launched); } catch (e) { log('[-] result.success: ' + e); }
      const self = this;
      const callback = String(this.onBiometricCapturedMethod.value || 'onBiometricCaptured');
      setTimeout(function () {
        try {
          Java.scheduleOnMainThread(function () {
            try {
              handleCaptureResult.call(self, fakeIntent, callback, 'Biometric');
              log('[+] Injected onBiometricCaptured success');
            } catch (e) {
              log('[-] handleCaptureResult: ' + e);
            }
          });
        } catch (e) {
          log('[-] scheduleOnMainThread: ' + e);
        }
      }, 300);
    };
  });
});
