/* This is the background page for gmail-crypt that communicates between gmail and the extension.
 *
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */

//Grouping all alerts in one place, easy to access. Consider moving .html to a format function, since they are heavily pattern based.
var gCryptAlerts = {
  gCryptAlertDecryptNoMessage : {id: 'gCryptAlertDecryptNoMessage', type: 'error', text: 'No OpenPGP message was found.',
    html: '<div class="alert alert-error" id="gCryptAlertDecryptNoMessage">No OpenPGP message was found.</div>' },
  gCryptUnableVerifySignature: {id: 'gCryptUnableVerifySignature', type: '', text: 'Mymail-Crypt For Gmail was unable to verify this message.',
    html: '<div class="alert" id="gCryptUnableVerifySignature">Mymail-Crypt For Gmail was unable to verify this message.</div>' },
  gCryptAbleVerifySignature: {id: 'gCryptAbleVerifySignature', type: 'success', text: 'Mymail-Crypt For Gmail was able to verify this message.',
    html: '<div class="alert alert-success" id="gCryptUnableVerifySignature">Mymail-Crypt For Gmail was able to verify this message.</div>'},
  gCryptAlertPassword: {id: 'gCryptAlertPassword', type: 'error', text: 'Mymail-Crypt For Gmail was unable to read your key. Is your password correct?',
    html: '<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt For Gmail was unable to read your key. Is your password correct?</div>'},
  gCryptAlertDecrypt: {id: 'gCryptAlertDecrypt', type: 'error', text: 'Mymail-Crypt for Gmail was unable to decrypt this message.',
    html: '<div class="alert alert-error" id="gCryptAlertDecrypt">Mymail-Crypt for Gmail was unable to decrypt this message.</div>'},
  gCryptAlertEncryptNoUser: {id: 'gCryptAlertEncryptNoUser', type: 'error', text: 'Unable to find a key for the given user. Have you inserted their public key?',
    html: '<div class="alert alert-error" id="gCryptAlertEncryptNoUser">Unable to find a key for the given user. Have you inserted their public key?</div>'},
  gCryptAlertEncryptNoPrivateKeys: {id: 'gCryptAlertEncryptNoPrivateKeys', type: 'error', text: 'Unable to find a private key for the given user. Have you inserted yours in the Options page?',
    html: '<div class="alert alert-error" id="gCryptAlertEncryptNoUser">Unable to find a private key for the given user. Have you inserted yours in the Options page?</div>'}
};


function getOption(optionName) {
	openpgp.config.read();
	var gCryptSettings = openpgp.config.config.gCrypt;
	
	if(!gCryptSettings) {
		return;
	} else {
		return gCryptSettings[optionName];
	}
}

function getPublicKeys(emails){
  var keys = {};
  var includeMyKey = getOption('includeMyself');
  for(var email in emails){
    try{
      if(emails[email].length>0){
          keys[emails[email]] = openpgp.keyring.getPublicKeyForAddress(emails[email])[0].armored;
      }
      if (includeMyKey) {
        var myKey = openpgp.keyring.getPublicKeysForKeyId(request.myKeyId)[0];
        var myEmail = gCryptUtil.parseUser(myKey.obj.userIds[0].text).userEmail;
        keys[myEmail] = myKey.armored;
      }
    }
    catch(e){

    }
  }
  return keys;
}

function getPublicKey(email) {
  return openpgp.keyring.getPublicKeyForAddress(email);
}

function getMyKeyId(callback){
  if(openpgp.keyring.privateKeys.length > 0) {
    return openpgp.keyring.privateKeys[0].keyId;
  }
}

function getPrivateKeys() {
  return openpgp.keyring.privateKeys;
}

function getPrivateKey(email) {
  return openpgp.keyring.getPrivateKeyForAddress(email);
}

function prepareAndValidatePrivateKey(password) {
  var privKey = openpgp.read_privateKey(getPrivateKeys()[0].armored)[0];
  if(!privKey) {
    return gCryptAlerts.gCryptAlertEncryptNoPrivateKeys;
  }
  if (!privKey.decryptSecretMPIs()) {
    if (!privKey.decryptSecretMPIs(password)) {
      return gCryptAlerts.gCryptAlertPassword;
    }
  }
  return privKey;
}

function prepareAndValidateKeysForRecipients(recipients) {
  if(recipients.email.length === 0){
    return gCryptAlerts.gCryptAlertEncryptNoUser;
  }

  var keys = getPublicKeys(recipients.email);

  var responseKeys = Object.keys(keys);
  if(responseKeys.length === 0){
    return gCryptAlerts.gCryptAlertEncryptNoUser;
  }
  //We do the section below because when looking up keys from keyring, they're not necessarily in proper form.
  var publicKeys = [];
  for(var r in responseKeys){
    var recipient = responseKeys[r];
    if(keys[recipient].length === 0) {
      return gCryptAlerts.gCryptAlertEncryptNoUser;
    }
    else{
      publicKeys.push(openpgp.read_publicKey(keys[recipient])[0]);
    }
  }

  return publicKeys;
}

function encryptAndSign(recipients, message, password) {
  var privKey = prepareAndValidatePrivateKey(password);
  if(privKey && privKey.type && privKey.type == "error") {
    return privKey;
  }
  var publicKeys = prepareAndValidateKeysForRecipients(recipients);
  if(publicKeys && publicKeys.type && publicKeys.type == "error") {
    return publicKeys;
  }
  var cipherText = openpgp.write_signed_and_encrypted_message(privKey,publicKeys, message);
  return cipherText;
}

function encrypt(recipients, message) {
  var publicKeys = prepareAndValidateKeysForRecipients(recipients);
  if(publicKeys && publicKeys.type && publicKeys.type == "error") {
    return publicKeys;
  }
  var cipherText = openpgp.write_encrypted_message(publicKeys, message);
  return cipherText;
}

function sign(message, password) {
  var privKey = prepareAndValidatePrivateKey(password);
  if(privKey && privKey.type && privKey.type == "error") {
    return privKey;
  }
  var cipherText = openpgp.write_signed_message(privKey, message);
  return cipherText;
}

function decryptHelper(msg, material, sessionKey, publicKeys){
  var status = [];
  try{
      var decryptResult = msg.decryptAndVerifySignature(material, sessionKey, publicKeys);
        if(decryptResult.text !== ''){
            if(decryptResult.validSignatures.indexOf(false)>=0 || decryptResult.validSignatures.length === 0){
                 status.push(gCryptAlerts.gCryptUnableVerifySignature);
            }
            else{
                status.push(gCryptAlerts.gCryptAbleVerifySignature);
            }
            return {decrypted: true, status: status, text: decryptResult.text};
            }
        }
    catch(e){ //This means that the initial key is not the one we need
    }
    return {decrypted: false};
}

function decrypt(senderEmail, msg, password) {
  var errors = [];
  msg = openpgp.read_message(msg);
  if(msg === null){
    errors.push(gCryptAlerts.gCryptAlertDecryptNoMessage);
    return { decrypted: false, status: errors};
  }
  //msg is an array so we need to take the first
  msg = msg[0];
  var privateKeys = getPrivateKeys();
  var publicKeys = getPublicKey(senderEmail);
  for (var publicKey in publicKey) {
    publicKeys[publicKey].obj = openpgp.read_publicKey(publicKeys[publicKey].armored)[0];
  }
  privateKeyLoop:
  for(var r = 0; r < privateKeys.length;r++){
    var key = openpgp.read_privateKey(privateKeys[r].armored)[0];
    if(!key.hasUnencryptedSecretKeyData){
      if(!key.decryptSecretMPIs(password)) {
        errors.push(gCryptAlerts.gCryptAlertPassword);
        continue privateKeyLoop;
      }
    }

    var material = {key: key , keymaterial: key.privateKeyPacket};
    for(var sessionKeyIterator in msg.sessionKeys){
      var sessionKey = msg.sessionKeys[sessionKeyIterator];
      var keymat = {key: key , keymaterial: key.privateKeyPacket};
      decryptResult = decryptHelper(msg, keymat, sessionKey, publicKeys);
      if (decryptResult.decrypted) {
        return decryptResult;
      }
      for (var j = 0; j < key.subKeys.length; j++) {
        keymat = { key: key, keymaterial: key.subKeys[j]};
        if(!keymat.keymaterial.hasUnencryptedSecretKeyData) {
          keymat.keymaterial.decryptSecretMPIs(password);
        }
        decryptResult = decryptHelper(msg, keymat, sessionKey, publicKeys);
        if (decryptResult.decrypted) {
          return decryptResult;
        }
      }
    }
  }
  return {decrypted: false, status: errors};
}


chrome.extension.onRequest.addListener(function(request,sender,sendResponse){
    openpgp.keyring.init(); //We need to handle changes that might have been made.
    var result;
    if(request.method == "encryptAndSign"){
      result = encryptAndSign(request.recipients, request.message, request.password);
      sendResponse(result);
    }
    if(request.method == "encrypt"){
      result = encrypt(request.recipients, request.message);
      sendResponse(result);
    }
    if(request.method == "sign"){
      result = sign(request.message, request.password);
      sendResponse(result);
    }
    if(request.method == "decrypt"){
      result = decrypt(request.senderEmail, request.msg, request.password);
      sendResponse(result);
    }
	if (request.method == "verifyPassword") {
		result = prepareAndValidatePrivateKey(request.password);
		sendResponse(result);
	}
    if(request.method == "getOption"){
      result = getOption(request.option);
      sendResponse(result);
    }
    if(request.method == "getConfig"){
        sendResponse(openpgp.config);
    }
    else{
    }
});

function onLoad(){
    openpgp.init();
}

document.onload = onLoad();

function showMessages(str){
  console.log(str);
}
