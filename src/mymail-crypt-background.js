/* This is the background page for gmail-crypt that communicates between gmail and the extension.
 *
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */

'use strict';

const openpgp = require('openpgp');
const _ = require('lodash');
const gCryptUtil = require('./mymail-crypt-util.js');

let keyring;
let config;

// Grouping all alerts in one place, easy to access. Consider moving .html to a format function, since they are heavily pattern based.
const gCryptAlerts = {
  gCryptAlertDecryptNoMessage: {
    id: 'gCryptAlertDecryptNoMessage',
    type: 'error',
    text: 'No OpenPGP message was found.',
    class: 'alert-error'
  },
  gCryptAlertDecryptNoCleartextMessage: {
    id: 'gCryptAlertDecryptNoCleartextMessage',
    type: 'error',
    text: 'No signed, cleartext OpenPGP message was found. Was this message also encrypted?',
    class: 'alert-error'
  },
  gCryptUnableVerifySignature: {
    id: 'gCryptUnableVerifySignature',
    type: '',
    text: 'Mymail-Crypt For Gmail was unable to verify this message.',
    class: ''
  },
  gCryptAbleVerifySignature: {
    id: 'gCryptAbleVerifySignature',
    type: 'success',
    text: 'Mymail-Crypt For Gmail was able to verify this message.',
    class: 'alert-success'
  },
  gCryptAlertPassword: {
    id: 'gCryptAlertPassword',
    type: 'error',
    text: 'Mymail-Crypt For Gmail was unable to read your key. Is your password correct?',
    class: 'alert-error'
  },
  gCryptAlertDecrypt: {
    id: 'gCryptAlertDecrypt',
    type: 'error',
    text: 'Mymail-Crypt for Gmail was unable to decrypt this message.',
    class: 'alert-error'
  },
  gCryptAlertEncryptNoUser: {
    id: 'gCryptAlertEncryptNoUser',
    type: 'error',
    text: 'Unable to find a public key for the recipients. Have you inserted their public key(s)?',
    class: 'alert-error'
  },
  gCryptAlertEncryptNoPrivateKeys: {
    id: 'gCryptAlertEncryptNoPrivateKeys',
    type: 'error',
    text: 'Unable to find your private key. Check the Options page.',
    class: 'alert-error'
  }
};

function getKeys(keyIds, keyringSet) {
  const keys = [];
  keyIds.forEach(function (keyId) {
    keys.push(keyringSet.getForId(keyId.toHex(), true));
  });
  return keys;
}

function prepareAndValidatePrivateKey(password, from) {
  const privateKeys = keyring.privateKeys.getForAddress(from);
  if (_.isEmpty(privateKeys)) {
    return gCryptAlerts.gCryptAlertEncryptNoPrivateKeys;
  }

  const privateKey = _(privateKeys).find(function (key) {
    return (key.decrypt() || key.decrypt(password));
  });

  return privateKey || gCryptAlerts.gCryptAlertPassword;
}

function prepareAndValidateKeysForRecipients(recipients, from) {
  let keys = [];
  const includeMyKey = true; // do we want this to be configurable?

  _(recipients.email).each(function (email) {
    const publicKeyResult = keyring.publicKeys.getForAddress(email);
    if (!_.isEmpty(publicKeyResult)) {
      keys.push(publicKeyResult[0]);
    }
  });

  if (_.isEmpty(keys) || (_.size(recipients.email) !== _.size(keys))) {
    return gCryptAlerts.gCryptAlertEncryptNoUser;
  }

  if (includeMyKey) {
    keys = _.uniq(_.compact(keys.concat(keyring.publicKeys.getForAddress(from))));
  }
  return keys;
}

function encryptAndSign(recipients, from, message, password, callback) {
  let promise;
  const privKey = prepareAndValidatePrivateKey(password, from);
  const publicKeys = prepareAndValidateKeysForRecipients(recipients, from);
  if (privKey.type && privKey.type === 'error') {
    promise = Promise.resolve(privKey);
  }
  else if (publicKeys.type && publicKeys.type === 'error') {
    promise = Promise.resolve(publicKeys);
  }
  else {
    promise = openpgp.encrypt({ data: message, publicKeys, privateKeys: privKey });
  }
  handleResponsePromise(promise, callback);
}

function sign(message, password, from, callback) {
  let promise;
  const privKey = prepareAndValidatePrivateKey(password, from);
  if (privKey && privKey.type && privKey.type === 'error') {
    promise = Promise.resolve(privKey);
  }
  else {
    // TODO use privKeys because openpgp.js wants this to be an array. Should unify it's interface.
    const privKeys = [privKey];
    promise = openpgp.signClearMessage(privKeys, message);
  }
  handleResponsePromise(promise, callback);
}

const decryptResult = function (decrypted, status, result, callback) {
  const output = {};
  output.decrypted = decrypted;
  output.status = status;
  output.result = result;
  const promise = Promise.resolve(output);
  handleResponsePromise(promise, callback);
};

function decrypt(senderEmail, msg, password, callback) {
  const status = [];
  let readMsg;
  try {
    readMsg = openpgp.message.readArmored(msg);
  }
  catch (e) {
    status.push(gCryptAlerts.gCryptAlertDecryptNoMessage);
    decryptResult(false, status, undefined, callback);
  }
  const keyIds = readMsg.getEncryptionKeyIds();
  const privateKeys = _.compact(getKeys(keyIds, keyring.privateKeys));
  if (_.size(privateKeys) === 0) {
    status.push(gCryptAlerts.gCryptAlertEncryptNoPrivateKeys);
    decryptResult(false, status, undefined, callback);
  }
  const publicKeys = keyring.publicKeys.getForAddress(senderEmail);
  for (let r = 0; r < privateKeys.length; r++) {
    const key = privateKeys[r];
    if (!key.decryptKeyPacket(keyIds, password)) {
      // TODO this could be generate false positive errors if we privateKeys really has multiple hits
      status.push(gCryptAlerts.gCryptAlertPassword);
    }

    const promise = openpgp.decrypt({ publicKeys, privateKey: key, message: readMsg });
    promise.then(function (result) {
      validateResultSignatures(result, callback);
    }).catch(function (exception) {
      console.log(JSON.stringify(exception));
      status.push(gCryptAlerts.gCryptAlertDecrypt);
      decryptResult(false, status, undefined, callback);
    });
  }
}

function validateResultSignatures(result, callback) {
  let signatureBooleans;
  const status = [];
  let verified = false;
  if (result.signatures) {
    signatureBooleans = _.map(result.signatures, function (signature) {
      return signature.valid;
    });
    verified = signatureBooleans.indexOf('false') < 0;
  }
  if (verified) {
    status.push(gCryptAlerts.gCryptAbleVerifySignature);
  }
  else {
    status.push(gCryptAlerts.gCryptUnableVerifySignature);
  }
  decryptResult(true, status, result, callback);
}

function verify(senderEmail, msg, callback) {
  const status = [];
  let readMsg;
  try {
    readMsg = openpgp.cleartext.readArmored(msg);
  }
  catch (e) {
    status.push(gCryptAlerts.gCryptAlertDecryptNoCleartextMessage);
    decryptResult(false, status, undefined, callback);
  }
  const publicKeys = keyring.publicKeys.getForAddress(senderEmail);
  const promise = openpgp.verifyClearSignedMessage(publicKeys, readMsg);
  promise.then(function (result) {
    validateResultSignatures(result, callback);
  }).catch(function (exception) {
    console.log(JSON.stringify(exception));
    status.push(gCryptAlerts.gCryptUnableVerifySignature);
    decryptResult(false, status, undefined, callback);
  });
}

function handleResponsePromise(promise, callback) {
  promise.then(function (result) {
    callback(result);
  });
}

chrome.extension.onRequest.addListener(function (request, sender, callback) {
  // config can change at anytime, reload on request
  loadConfig();
  // keys can be changed in options. This prevents force page reloading
  keyring.publicKeys.keys = keyring.storeHandler.loadPublic();
  keyring.privateKeys.keys = keyring.storeHandler.loadPrivate();

  if (request.method === 'encryptAndSign') {
    encryptAndSign(request.recipients, request.from, request.message, request.password, callback);
  }
  else if (request.method === 'sign') {
    sign(request.message, request.password, request.from, callback);
  }
  else if (request.method === 'decrypt') {
    decrypt(request.senderEmail, request.msg, request.password, callback);
  }
  else if (request.method === 'verify') {
    verify(request.senderEmail, request.msg, callback);
  }
  else if (request.method === 'getOption') {
    callback(gCryptUtil.getOption(config, request.option, request.thirdParty));
  }
  else {
    throw new Error('Unsupported Operation');
  }
});

// function setupDraftStopping() {
//   const enabled = gCryptUtil.getOption(config, 'stopAutomaticDrafts', true, setupDraftStopping);
//   if (enabled) {
//     const filter = { urls: ['*://mail.google.com/mail/u/*'], types: ['xmlhttprequest'] };
//     chrome.webRequest.onBeforeRequest.addListener(determineIfRequestDraftSaving, filter, ['requestBody', 'blocking']);
//   }
// }

// function determineIfRequestDraftSaving(details) {
//   // We want to make sure: 1 -- this is a post, also it's either an autosave URL or is sending body/subject and is not a send email request
//   if (details.method === 'POST' && (_.contains(details.url, 'autosave') ||
//                                    (!_.contains(details.url, 'rid=mail') &&
//                                    (details.requestBody && details.requestBody.formData && (
//                                     'body' in details.requestBody.formData ||
//                                     'subject' in details.requestBody.formData))))) {
//     return { cancel: true };
//   }
// }

const loadConfig = function () {
  config.read();
  for (const key of Object.keys(config.config)) {
    openpgp.config[key] = config.config[key];
  }
};

const initialize = function () {
  keyring = new openpgp.Keyring();
  gCryptUtil.migrateOldKeys(keyring);
  // TODO openpgp.js needs to improve config support, this is a hack.
  config = new openpgp.config.localStorage();
  loadConfig();

  // TODO this is a new potential avenue for draft blocking
  // setupDraftStopping();
};

document.onload = initialize();
