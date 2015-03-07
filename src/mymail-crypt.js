/* This is the general class for gmail-crypt that runs within gmail context.
 *
 * Copyright 2011 - 2013 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */

var rootElement = $(document);

//This clear and save is specific to the embedded reply composes
function clearAndSaveReply(event){
  rootElement.find('[class*="gA gt"] [g_editable]').html('');
  var replyForm = rootElement.find('[class*="gA gt"] form[method="POST"]');
  replyForm.attr('id', replyForm.attr('old-id'));
  $(event.target).find('a').click();
  return true;
}

function clearAndSave(event){
  //Find the related compose box, and blank out, then proceed as if normal closing.
  //TODO could probably clean this up to be more DRY
  $(event.target).parents('[class="I5"]').find('[g_editable]').html('');
  saveDraft(event);
}

function saveDraft(event){
  var form = $(event.target).parents('[class="I5"]').find('form[method="POST"]');
  form.attr('id', form.attr('old-id'));
  return true;
}

function rebindSendButtons(){
  var sendButtons = rootElement.find('td[class="gU Up"] > div > [role="button"]');
  sendButtons.mousedown(saveDraft);

  var closeComposeButtons = rootElement.find('[class="Ha"]');
  closeComposeButtons.mousedown(clearAndSave);

  if (rootElement.find('[class*="gA gt"]')) {
    rootElement.find('.oo').click(clearAndSaveReply);
    rootElement.find('.adf').click(clearAndSaveReply);
  }
}

function getContents(form, event){
  //g_editable is intended to work with Gmail's new broken out window approach.
  //we search based on event because it works well in case multiple compose windows are open
  var msg;
  var g_editable = $(event.currentTarget).parents('.I5').find('[g_editable]').first();
  if (g_editable && g_editable.length > 0 && g_editable.html()) {
    msg = g_editable.html().replace(/(<div>)/g,'\n');
    msg = msg.replace(/(<\/div>)/g,'');
    return {g_editable: g_editable, msg: msg};
  }
  var textarea = $('textarea[spellcheck="true"]',form);
  var iframe = $('iframe',form).contents().find('body');
  try{
    msg = iframe.html().replace(/(<div>)/g,'\n');
    msg = msg.replace(/(<\/div>)/g,'');
  }
  catch(e){
    msg = textarea.val();
  }
  return {textarea: textarea, iframe: iframe, msg: msg };
}

//This could be streamlined as google has change this mechanism frequently.
function writeContents(contents, message){
  if (contents.g_editable) {
    message = message.split('\n').join('<br/>');
    contents.g_editable.html(message);
  }
  try{
    contents.iframe[0].innerText = message;
  }
  catch(e){
    //No iframe (rich editor) entry, only plaintext loaded
  }
  try{
    contents.textarea.val(message);
  }
  catch(e){
    //No plaintext editor
  }

}

function getRecipients(form, event){
  var recipients = {};
  recipients.email = [];
  var emailsParent = $(event.currentTarget).parents('.I5').find('[email]').last().parent().parent();
  if (emailsParent && emailsParent.length > 0) {
    emailsParent.find('[email]').each(function() {
      recipients.email.push($(this).attr("email"));
    });
  }
  return recipients;
}

function findSender(form) {
  // First look at the form (this works for multi-account users)
  var from = form.find('[name="from"]').val();
  // These selectors have been slightly unstable so taking a priority based approach
  var selectors = [ '.gb_ja', '.gb_ia'];
  $.each(selectors, function(selector) {
    if ($.isEmptyObject(from) || from.indexOf('@') < 0) {
      from = $(selector).text();
    }
  });

  // This is a backup in case all of the other means have failed.
  if ($.isEmptyObject(from) || from.indexOf('@') < 0) {
    from = $('.gb_ga').closest(':contains("@")').find(':contains("@")').text();
  }

  return from;
}

// Cheating at multisync
var pendingBackgroundCall = false;
function sendAndHandleBackgroundCall(event){
  if (pendingBackgroundCall) {
    return;
  }
  pendingBackgroundCall = true;
  var form = $(event.currentTarget).parents('.I5').find('form');
  form.find('.alert').hide();
  var contents = getContents(form, event);
  var password = form.find('#gCryptPasswordEncrypt').val();
  var recipients = getRecipients(form, event);
  var from = findSender(form);

  $(event.currentTarget).parent().find('[class*=btn]').addClass('disabled');

  sendExtensionRequestPromise({method: event.data.action, recipients: recipients, from: from, message: contents.msg, password: password})
  .then(function(response) {
    if(response.type && response.type == "error") {
      showAlert(response, form);
    }
    $(event.currentTarget).parent().find('[class*=btn]').removeClass('disabled');
    pendingBackgroundCall = false;
    writeContents(contents, response);
  });
}

function getMessage(objectContext){
  var msg;
  //we need to use regex here because gmail will automatically form \n into <br> or <wbr>, strip these out
  //I'm not entirely happy with these replace statements, perhaps there can be a different approach
  var element = $(event.currentTarget).closest('div[class="gs"]').find('[class*="ii gt"] div');
  msg = element.html().replace(/\n/g,"");
  msg = msg.replace(/(<br><\/div>)/g,'\n'); //we need to ensure that extra spaces aren't added where gmail puts a <div><br></div>
  msg = msg.replace(/(<\/div>)/g,'\n');
  msg = msg.replace(/(<br>)/g,'\n');

  //originally stripped just <br> and <wbr> but gmail can add other things such as <div class="im">
  msg = msg.replace(/<(.*?)>/g,'');
  return [element, msg];
}

function sendAndHandleDecryptAndVerify(event){
  rootElement.find('.alert').hide();
  var password = $(this).parent().parent().find('form[class="form-inline"] input[type="password"]').val();
  var objectContext = this;
  var setup = getMessage(objectContext);
  var element = setup[0];
  var msg = setup[1];
  var senderEmail = $(objectContext).parents('div[class="gE iv gt"]').find('span [email]').attr('email');
  chrome.extension.sendRequest({method: event.data.action, senderEmail:senderEmail, msg: msg, password: password}, function(response){
    $.each(response.status, function(key, status) {
      $(objectContext).parents('div[class="gE iv gt"]').append(status.html);
    });
    if (response.decrypted) {
      element.html(response.result.text.replace(/\n/g,'<br>'));
    }
  });
}

function stopAutomaticDrafts(){
  //Find all open compose windows, then set them not to save
  var forms = rootElement.find('.I5 form[method="POST"]');//rootElement.find('[class="nH Hd"] form[method="POST"]');
  $.each(forms, function(key, value) {
    //We change the ID of the form so that gmail won't upload drafts. Store old in "old-id" attribute for restoration.
    var form = $(value);
    var formId = form.attr('id');
    if (formId != 'gCryptForm') {
      form.attr('old-id', formId);
      form.attr('id','gCryptForm');
    }
  });

  rebindSendButtons();
  //setTimeout here because we need to check if new windows are opened
  setTimeout(stopAutomaticDrafts, 2000);
}

function showAlert(alert, form) {
  if(form) {
    var alertInForm = form.find('#'+alert.id);
    if (alertInForm && alertInForm.length > 0) {
      alertInForm.show();
      return;
    }
  }
  showModalAlert(alert.html);
}

function showModalAlert(message) {
  $('#gCryptModalBody').html(message);
  $('#gCryptModal').modal('show');
}

function sendExtensionRequestPromise(request) {
  var deferred = $.Deferred();
  chrome.extension.sendRequest(request, function(response){
    deferred.resolve(response);
  });
  return deferred.promise();
}

function composeIntercept(ev) {
  var composeBoxes = $('.n1tfz');
  if (composeBoxes && composeBoxes.length > 0) {
    composeBoxes.each(function(){
      var composeMenu = $(this).parent().parent().parent();
      if (composeMenu && composeMenu.length> 0 && composeMenu.find('#gCryptEncrypt').length === 0) {
        var maxSizeCheck = composeMenu.parent().parent().parent().parent().parent().find('[style*="max-height"]');
        //The below logic is for inserting the form into the windows, different behavior for in window compose and popout compose.
        var encryptionFormOptions = '<span id="gCryptEncrypt" class="btn-group" style="float:right"><a class="btn" href="#" id="encryptAndSign"><img src="'+chrome.extension.getURL("images/encryptIcon.png")+'" width=13 height=13/> Encrypt and Sign</a><a class="btn" href="#" id="encrypt">Encrypt</a><a class="btn" href="#" id="sign">Sign</a></span>';

        var encryptionForm = '<form class="form-inline" style="float:right"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordEncrypt" style="font-size:12px;margin-top:5px;"></form>';

        if (maxSizeCheck && maxSizeCheck.length > 0 && maxSizeCheck.css('max-height') === maxSizeCheck.css('height')) {
          composeMenu.find('.n1tfz :nth-child(6)').after('<td class="gU" style="min-width: 360px;">' + encryptionFormOptions + '</td><td class="gU">' + encryptionForm + '</td>');
        }
        else {
          composeMenu.append(encryptionFormOptions + encryptionForm);
          composeMenu.css("height","80px");
        }
        composeMenu.find('#encryptAndSign').click({action: "encryptAndSign"}, sendAndHandleBackgroundCall);
        composeMenu.find('#encrypt').click({action: "encrypt"}, sendAndHandleBackgroundCall);
        composeMenu.find('#sign').click({action: "sign"}, sendAndHandleBackgroundCall);
        composeMenu.find('form[class="form-inline"]').submit({action: "encryptAndSign"}, function(event){
          sendAndHandleBackgroundCall(event);
          return false;
        });
      }
    });
    sendExtensionRequestPromise({method: 'getOption', option: 'stopAutomaticDrafts', thirdParty: true})
    .then(function(response) {
      if(response === true){
        stopAutomaticDrafts();
      }
    });
  }

  var viewTitleBar = rootElement.find('td[class="gH acX"]');
  if (viewTitleBar && viewTitleBar.length > 0) {
    viewTitleBar.each(function(v) {
      if ($(this).find('#gCryptDecrypt').length === 0) {
        $(this).prepend('<span id="gCryptDecrypt"><a class="btn" action="decrypt" id="decrypt"><img src="'+chrome.extension.getURL("images/decryptIcon.png")+'" width=13 height=13 />Decrypt</a></span>');
        $(this).find('#decrypt').click({action: "decrypt"}, sendAndHandleDecryptAndVerify);
        $(this).append('<form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordDecrypt"></form>');
        $(this).find('form[class="form-inline"]').submit(function(event){
          $(this).parent().find('a[action="decrypt"]').click();
          return false;
        });
        $(this).prepend('<span id="gCryptVerify"><a class="btn" id="verify">Verify Signature</a></span>');
        $(this).find('#verify').click({action: "verify"}, sendAndHandleDecryptAndVerify);
      }
    });
  }

  var gmailCryptModal = $('#gCryptModal');
  if(gmailCryptModal && gmailCryptModal.length === 0) {
    $('.aAU').append('<div id="gCryptModal" class="modal hide fade" tabindex=-1 role="dialog"><div class="modal-header">' +
                     '<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>' +
                     '<h3>Mymail-Crypt for Gmail</h3></div><div id="gCryptModalBody" class="modal-body"></div></div>');
    $('#gCryptModal').click(function() {
      $('#gCryptModal').modal('hide');
    });
  }
}

//This animation strategy inspired by http://blog.streak.com/2012/11/how-to-detect-dom-changes-in-css.html
//based on http://davidwalsh.name/detect-node-insertion changes will depend on CSS as well.
var insertListener = function(event) {
  if (event.animationName == "composeInserted") {
    composeIntercept();
  }
};

// TODO this used to be more reliable to call the eventlistener in $(document).ready idk why it's not now
//$(document).ready(onLoadAnimation);
document.addEventListener("webkitAnimationStart", insertListener, false);
