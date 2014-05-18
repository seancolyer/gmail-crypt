var keyring;
var config;
var privateKeyFormToggle = true;
var publicKeyFormToggle = true;
var generateKeyFormToggle = true;

function showMessages(msg){
  console.log(msg);
}

function generateKeyPair(){
  $('.alert').hide();
  var form = $('#generateKeyPairForm');
  var generateOptions = {
          numBits: parseInt(form.find('#numBits').val(), 10),
          userId: form.find('#name').val() + ' <' + form.find('#email').val() + '>',
          passphrase: form.find('#password').val()
  };
  var keyPair = openpgp.generateKeyPair(generateOptions);
  keyring.privateKeys.importKey(keyPair.privateKeyArmored);
  keyring.publicKeys.importKey(keyPair.publicKeyArmored);
  keyring.store();
  parsePrivateKeys();
  parsePublicKeys();
}

function insertPrivateKey(){
  $('.alert').hide();
  var privKey = $('#newPrivateKey').val();
  var privKeyPassword = $('#newPrivateKeyPassword').val();
  try{
    var importResult = keyring.privateKeys.importKey(privKey);
    if(importResult == null){
      keyring.store();
      parsePrivateKeys();
      return true;
    }
    else{
      $('#insertPrivateKeyForm').prepend('<div class="alert alert-error" id="gCryptAlertOpenpgpjs">' + importResult  + '</div>');
    }
  }
  catch(e){
    $('#insertPrivateKeyForm').prepend('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt for Gmail was unable to read your key. It would be great if you could contact us so we can help figure out what went wrong.</div>');
  }
  return false;
}

function insertPublicKey(){
  $('.alert').hide();
  var pubKey = $('#newPublicKey').val();
  try{
    keyring.publicKeys.importKey(pubKey);
    keyring.store();
    parsePublicKeys();
    return true;
  }
  catch(e){
  }
  $('#insertPublicKeyForm').prepend('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt for Gmail was unable to read this key. It would be great if you could contact us so we can help figure out what went wrong.</div>');
  return false;
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
    $('#' + domPrefix + 'KeyTable>tbody').append('<tr><td class="removeLink" id="' + k + '"><a href="#">remove</a></td>' +
                                       '<td>' + user.userName + '</td>' +
                                       '<td>' + user.userEmail + '</td>' +
                                       '<td><a href="#' + domPrefix + k +'" data-toggle="modal">show key</a><div class="modal" id="' + domPrefix + k + '"><div class="modal-body"><a class="close" data-dismiss="modal">Close</a><br/ ><pre>' + key.armor() + '</pre></div></div></td></tr>');
    $('#' + domPrefix + k).hide();
    $('#' + domPrefix + k).modal({backdrop: true, show: false});
  }
  $('#' + domPrefix + 'KeyTable .removeLink').click(function(e){
    keys.splice(e.currentTarget.id);
    keyring.store();
    parseKeys(keys, domPrefix);
  });
}

/**
 * We use openpgp.config for storing our options.
 */
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
  config.read();
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
