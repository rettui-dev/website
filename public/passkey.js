// Passkeys in the browser: the one place that calls navigator.credentials. The server hands out
// options as JSON (ids and the challenge as base64url text) and takes the answer as JSON too. Where
// the browser has PublicKeyCredential.parse*FromJSON and toJSON (recent Chrome, Safari and Firefox)
// they do the conversion; elsewhere it is done by hand below, with the same result.
//
// window.rettuiPasskey.supported() says whether this browser can do passkeys at all.
// create(options) and get(options) give a promise of the JSON answer. A failure rejects with an Error
// whose name is the browser's: NotAllowedError means the visitor cancelled (or the prompt timed out),
// InvalidStateError that this passkey is registered already. cancelled(error) tells the first.
// Nothing here is shown or sent anywhere: the callers do that.
(function () {
  'use strict';

  function bytesOf(text) {
    var b = String(text).replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    var bin = atob(b);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function textOf(buffer) {
    var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fail(name, message) {
    var e = new Error(message);
    e.name = name;
    return e;
  }

  function supported() {
    return typeof window.PublicKeyCredential === 'function'
      && typeof navigator === 'object' && navigator !== null && Boolean(navigator.credentials)
      && typeof navigator.credentials.create === 'function' && typeof navigator.credentials.get === 'function';
  }

  function need() {
    if (!supported()) throw fail('NotSupportedError', 'This browser cannot use passkeys.');
  }

  function has(name) {
    return typeof window.PublicKeyCredential[name] === 'function';
  }

  function descriptors(list) {
    return (Array.isArray(list) ? list : []).map(function (c) {
      var d = { type: c.type || 'public-key', id: bytesOf(c.id) };
      if (Array.isArray(c.transports)) d.transports = c.transports;
      return d;
    });
  }

  function creationOptions(json) {
    if (has('parseCreationOptionsFromJSON')) return window.PublicKeyCredential.parseCreationOptionsFromJSON(json);
    var o = {};
    Object.keys(json).forEach(function (k) { o[k] = json[k]; });
    o.challenge = bytesOf(json.challenge);
    o.user = { id: bytesOf(json.user.id), name: json.user.name, displayName: json.user.displayName };
    o.excludeCredentials = descriptors(json.excludeCredentials);
    return o;
  }

  function requestOptions(json) {
    if (has('parseRequestOptionsFromJSON')) return window.PublicKeyCredential.parseRequestOptionsFromJSON(json);
    var o = {};
    Object.keys(json).forEach(function (k) { o[k] = json[k]; });
    o.challenge = bytesOf(json.challenge);
    o.allowCredentials = descriptors(json.allowCredentials);
    return o;
  }

  function extensions(cred) {
    return typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {};
  }

  function registrationJson(cred) {
    if (typeof cred.toJSON === 'function') return cred.toJSON();
    var r = cred.response;
    var out = {
      id: cred.id,
      rawId: textOf(cred.rawId),
      type: cred.type,
      clientExtensionResults: extensions(cred),
      response: { clientDataJSON: textOf(r.clientDataJSON), attestationObject: textOf(r.attestationObject) }
    };
    if (typeof r.getTransports === 'function') out.response.transports = r.getTransports();
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    return out;
  }

  function assertionJson(cred) {
    if (typeof cred.toJSON === 'function') return cred.toJSON();
    var r = cred.response;
    var out = {
      id: cred.id,
      rawId: textOf(cred.rawId),
      type: cred.type,
      clientExtensionResults: extensions(cred),
      response: { clientDataJSON: textOf(r.clientDataJSON), authenticatorData: textOf(r.authenticatorData), signature: textOf(r.signature) }
    };
    if (r.userHandle) out.response.userHandle = textOf(r.userHandle);
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    return out;
  }

  // Runs one call into navigator.credentials. Any throw, synchronous or not, becomes a rejection.
  function run(call, toJson) {
    return new Promise(function (resolve) {
      need();
      resolve(call());
    }).then(function (cred) {
      if (!cred) throw fail('NotAllowedError', 'No passkey was given.');
      return toJson(cred);
    });
  }

  window.rettuiPasskey = {
    supported: supported,
    create: function (options) {
      return run(function () { return navigator.credentials.create({ publicKey: creationOptions(options) }); }, registrationJson);
    },
    get: function (options) {
      return run(function () { return navigator.credentials.get({ publicKey: requestOptions(options) }); }, assertionJson);
    },
    cancelled: function (error) {
      return Boolean(error) && error.name === 'NotAllowedError';
    }
  };
})();
