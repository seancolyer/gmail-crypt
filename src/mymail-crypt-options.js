var keyring;
var config;
var privateKeyFormToggle = true;
var publicKeyFormToggle = true;
var generateKeyFormToggle = true;

function generateKeyPair(){
  $('.alert').hide();
  var form = $('#generateKeyPairForm');
  var generateOptions = {
          numBits: parseInt(form.find('#numBits').val(), 10),
          userId: form.find('#name').val() + ' <' + form.find('#email').val() + '>',
          passphrase: form.find('#password').val()
  };
  var keyPair = openpgp.generateKeyPair(generateOptions);
  keyPair.then(function(result) {
    keyring.privateKeys.importKey(result.privateKeyArmored);
    keyring.publicKeys.importKey(result.publicKeyArmored);
    keyring.store();
    parsePrivateKeys();
    parsePublicKeys();
  });
}

function insertPrivateKey(){
  $('.alert').hide();
  var privKey = $('#newPrivateKey').val();
  return handleKeyringImportResponse(keyring.privateKeys.importKey(privKey), '#insertPrivateKeyForm');
}

function insertPublicKey(){
  $('.alert').hide();
  var pubKey = $('#newPublicKey').val();
  return handleKeyringImportResponse(keyring.publicKeys.importKey(pubKey), '#insertPublicKeyForm');
}

function handleKeyringImportResponse(importResult, selector) {
  if (importResult === null) {
    keyring.store();
    parsePublicKeys();
    parsePrivateKeys();
    return true;
  }
  else {
    $(selector).prepend('<div id="openpgpjs-error" class="alert alert-error"></div><div class="alert alert-error">Mymail-Crypt for Gmail was unable to read this key. It would be great if you could contact us so we can help figure out what went wrong.</div>');
    $(selector + ' #openpgpjs-error').text(importResult);
    return false;
  }
}

function parsePublicKeys(){
  var keys = keyring.publicKeys.keys;
  var domPrefix = "public";

  parseKeys(keys, domPrefix);
}

function parsePrivateKeys() {
  var keys = keyring.privateKeys.keys;
  var domPrefix = "private";

  parseKeys(keys, domPrefix);
}

function parseKeys(keys, domPrefix){
  $('#' + domPrefix + 'KeyTable>tbody>tr').remove();
  for(var k = 0; k < keys.length; k++) {
    var key = keys[k];
    var user = gCryptUtil.parseUser(key.users[0].userId.userid);
    $('#' + domPrefix + 'KeyTable>tbody').append('<tr id="keyRow'+ k + '"><td><a href="#" class="removeLink" id="' + k + '">remove</a></td>' +
                                       '<td class="userName"></td>' +
                                       '<td class="userEmail"></td>' +
                                       '<td><a href="#' + domPrefix + k +'" data-toggle="modal">show key</a><div class="modal" id="' + domPrefix + k + '"><div class="modal-body"><a class="close" data-dismiss="modal">Close</a><br/ ><pre class="keyText"></pre></div></div></td></tr>');
    // We need to set the userName and userEmail here via `text` calls because they are unsafe and need sanitized
    $('#' + domPrefix + 'KeyTable #keyRow'+ k + ' .userName').text(user.userName);
    $('#' + domPrefix + 'KeyTable #keyRow'+ k + ' .userEmail').text(user.userEmail);
    $('#' + domPrefix + 'KeyTable #keyRow'+ k + ' .keyText').text(key.armor());
    $('#' + domPrefix + k).hide();
    $('#' + domPrefix + k).modal({backdrop: true, show: false});
  }
  $('#' + domPrefix + 'KeyTable .removeLink').click(function(e){
    keys.splice(e.currentTarget.id, 1);
    keyring.store();
    parseKeys(keys, domPrefix);
  });
}

function saveOptions(){
  saveOptionForCheckbox('stopAutomaticDrafts', 'stopAutomaticDrafts', true);
  saveOptionForCheckbox('includeMyself', 'includeMyself', true);
  saveOptionForCheckbox('showComment', 'show_comment', false);
  saveOptionForCheckbox('showVersion', 'show_version', false);
}

function saveOptionForCheckbox(elementId, configKey, thirdParty) {
  if($('#' + elementId + ':checked').length == 1){
    gCryptUtil.setOption(config, configKey, true, thirdParty);
  } else {
    gCryptUtil.setOption(config, configKey, false, thirdParty);
  }

}

function loadOptions(){
  if (gCryptUtil.getOption(config, 'stopAutomaticDrafts', true)) {
    $('#stopAutomaticDrafts').attr('checked', true);
  }
  if (gCryptUtil.getOption(config, 'includeMyself', true)) {
    $('#includeMyself').attr('checked', true);
  }
  if (gCryptUtil.getOption(config, 'show_comment', false)) {
    $('#showComment').attr('checked', true);
  }
  if (gCryptUtil.getOption(config, 'show_version', false)) {
    $('#showVersion').attr('checked', true);
  }
}

function linkLocalFunction(event){
  $('.alert').hide();
  $('span').hide();
  if(event && event.currentTarget){
    $(event.currentTarget.hash).show();
  }
}

function onLoad(){
  keyring = new openpgp.Keyring();
  //TODO openpgp.js needs to improve config support, this is a hack.
  config = new openpgp.config.localStorage();
  try {
    config.read();
  }
  catch (e) {
    //no-op, makes more sense to handle this in finally since read can give null config
  }
  finally {
    if(_.isEmpty(config.config)) {
      config.config = openpgp.config;
      config.write();
    }
  }
  gCryptUtil.migrateOldKeys(keyring);
  parsePrivateKeys();
  parsePublicKeys();
  loadOptions();
  $('.linkLocal').click(linkLocalFunction).click();
  $('#homeSpan').show();
  $('#generateKeyPairForm').hide();
  $('#generateKeyPairTitle').click(function() {
    $('#generateKeyPairForm').toggle(generateKeyFormToggle);
    generateKeyFormToggle = !generateKeyFormToggle;
  });
  $('#insertPrivateKeyForm').hide();
  $('#insertPrivateKeyTitle').click(function() {
    $('#insertPrivateKeyForm').toggle(privateKeyFormToggle);
    privateKeyFormToggle = !privateKeyFormToggle;
  });
  $('#insertPublicKeyForm').hide();
  $('#insertPublicKeyTitle').click(function() {
    $('#insertPublicKeyForm').toggle(publicKeyFormToggle);
    publicKeyFormToggle = !publicKeyFormToggle;
  });
  $('#optionsFormSubmit').click(saveOptions);
  $('#insertPrivateKeyFormSubmit').click(insertPrivateKey);
  $('#generateKeyPairFormSubmit').click(generateKeyPair);
  $('#insertPublicKeyFormSubmit').click(insertPublicKey);
}

$(document).ready(onLoad());
