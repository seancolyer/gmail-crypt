/* This is the general class for gmail-crypt that runs within gmail context.
 *
 * Copyright 2011 - 2016 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */
'use strict';

const sanitizeHtml = require('sanitize-html');
const $ = require('jquery');

const rootElement = $(document);

const PAGE_INJECTION_SCRIPT = require('raw-unsafe!../dist/js/page-injected.bundle.js');

function getContents(form, event) {
  // g_editable is intended to work with Gmail's new broken out window approach.
  // we search based on event because it works well in case multiple compose windows are open
  let msg;
  const $gEditable = $(event.currentTarget).parents('.I5').find('[g_editable]').first();
  if ($gEditable && $gEditable.length > 0 && $gEditable.html()) {
    msg = $gEditable.html().replace(/(<div>)/g, '\n');
    msg = msg.replace(/(<\/div>)/g, '');
    return { $gEditable, msg };
  }
  const textarea = $('textarea[spellcheck="true"]', form);
  const iframe = $('iframe', form).contents().find('body');
  try {
    msg = iframe.html().replace(/(<div>)/g, '\n');
    msg = msg.replace(/(<\/div>)/g, '');
  }
  catch (e) {
    msg = textarea.val();
  }
  return { textarea, iframe, msg };
}

// This could be streamlined as google has change this mechanism frequently.
function writeContents(contents, message) {
  let parsedMessage = message;
  if (contents.$gEditable) {
    parsedMessage = message.split('\n').join('<br/>');
    contents.$gEditable.html(parsedMessage);
  }
  try {
    contents.iframe[0].innerText = parsedMessage;
  }
  catch (e) {
    // No iframe (rich editor) entry, only plaintext loaded
  }
  try {
    contents.textarea.val(parsedMessage);
  }
  catch (e) {
    // No plaintext editor
  }
}

function getRecipients(form, event) {
  const recipients = {};
  recipients.email = [];
  const emailsParent = $(event.currentTarget).parents('.I5')
      .find('[email]')
      .last()
      .parent()
      .parent();
  if (emailsParent && emailsParent.length > 0) {
    emailsParent.find('[email]').each(function () {
      recipients.email.push($(this).attr('email'));
    });
  }
  return recipients;
}

function findSender(form) {
  // First look at the form (this works for multi-account users)
  let from = form.find('[name="from"]').val();
  // These selectors have been slightly unstable so taking a priority based approach
  const selectors = ['.gb_ja', '.gb_ia'];
  $.each(selectors, function (selector) {
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
let pendingBackgroundCall = false;
function sendAndHandleBackgroundCall(event) {
  if (pendingBackgroundCall) {
    return;
  }
  pendingBackgroundCall = true;
  const form = $(event.currentTarget).parents('.I5').find('form');
  form.parent().find('.gCrypt-alert').remove();
  const contents = getContents(form, event);
  const password = form.find('#gCryptPasswordEncrypt').val();
  const recipients = getRecipients(form, event);
  const from = findSender(form);

  // TODO is this working?
  $(event.currentTarget).parent().find('button').addClass('disabled');

  sendExtensionRequestPromise({ method: event.data.action, recipients, from, message: contents.msg, password })
  .then(function (response) {
    pendingBackgroundCall = false;
    $(event.currentTarget).parent().find('button').removeClass('disabled');

    if (response.type && response.type === 'error') {
      const $errorEl = $(`<div class="gCrypt-alert encrypt-alert ${response.class}"><div class="alert-content">${response.text}</div><div class="gCrypt-close">X</div></div>`);
      $errorEl.find('.gCrypt-close').click(function () {
        $(this).parent().remove();
      });
      $(event.currentTarget).closest('div').prepend($errorEl);
    }
    else {
      writeContents(contents, response.data);
    }
  });
}

function getMessage() {
  let msg;
  // we need to use regex here because gmail will automatically form \n into <br> or <wbr>, strip these out
  // I'm not entirely happy with these replace statements, perhaps there can be a different approach
  const element = $(event.currentTarget).closest('div[class="gs"]').find('[class*="ii gt"] div');
  msg = element.html().replace(/\n/g, '');
  msg = msg.replace(/(<br><\/div>)/g, '\n'); // we need to ensure that extra spaces aren't added where gmail puts a <div><br></div>
  msg = msg.replace(/(<\/div>)/g, '\n');
  msg = msg.replace(/(<br.*?>)/g, '\n');

  // originally stripped just <br> and <wbr> but gmail can add other things such as <div class="im">
  msg = msg.replace(/<(.*?)>/g, '');
  return [element, msg];
}

let pendingDecrypt = false;
function sendAndHandleDecryptAndVerify(event) {
  if (pendingDecrypt) {
    return;
  }
  pendingDecrypt = true;

  rootElement.find('.gCrypt-alert').remove();
  const password = $(this).parent().parent().find('form[class="form-inline"] input[type="password"]')
      .val();
  const setup = getMessage();
  const element = setup[0];
  const msg = setup[1];
  const objectContext = this;
  const senderEmail = $(objectContext).parents('div[class="gE iv gt"]').find('span [email]').attr('email');
  chrome.extension.sendRequest({ method: event.data.action, senderEmail, msg, password }, function (response) {
    pendingDecrypt = false;
    $.each(response.status, function (key, status) {
      const $messageContainer = $(objectContext).parents('div[class="gE iv gt"]');
      $messageContainer.append(`<div class="gCrypt-alert decrypt-alert ${status.class}"><div class="alert-content">${status.text}</div><div class="gCrypt-close">X</div></div>`);
      $messageContainer.find('.gCrypt-close').click(function () {
        $(this).parent().remove();
      });
    });
    if (response.decrypted) {
      let text = response.result.data;
      text = sanitizeHtml(text.replace(/\n/g, '<br>'));
      element.html(text);
    }
  });
}


function stopAutomaticDrafts() {
  const scriptId = 'gCrypt-injection';

  if (!document.getElementById(scriptId)) {
    const injectionTag = document.createElement('script');
    injectionTag.type = 'text/javascript';
    injectionTag.text = PAGE_INJECTION_SCRIPT;
    document.body.appendChild(injectionTag);
  }

  const $iframes = $('iframe');
  $iframes.each(function () {
    try {
      const thisDoc = this.contentWindow.document;
      if (!thisDoc.getElementById(scriptId)) {
        const scriptObj = thisDoc.createElement('script');
        scriptObj.type = 'text/javascript';
        scriptObj.id = scriptId;
        scriptObj.innerHTML = PAGE_INJECTION_SCRIPT;
        thisDoc.body.appendChild(scriptObj);
      }
    }
    catch (e) {
      console.log(`Cannot overwrite: ${e}`);
    }
  });
}

function sendExtensionRequestPromise(request) {
  const deferred = new $.Deferred();
  chrome.extension.sendRequest(request, function (response) {
    deferred.resolve(response);
  });
  return deferred.promise();
}

function composeIntercept() {
  const composeBoxes = $('.n1tfz');
  if (composeBoxes && composeBoxes.length > 0) {
    composeBoxes.each(function () {
      const composeMenu = $(this).parent().parent().parent();
      if (composeMenu && composeMenu.length > 0 && composeMenu.find('.gCrypt-button-group').length === 0) {
        // The below logic is for inserting the form into the windows, different behavior for in window compose and popout compose.
        const encryptionFormOptions =
            `<span class="gCrypt-button-group" style="float:right">
              <button id="encryptAndSign" class="" title="Encrypt and Sign Message">
                <img src="${chrome.extension.getURL('images/ic_lock_black_48px.svg')}" width=16 height=16/>
              </button>
              <button id="sign" class="" title="Sign Message">
                <img src="${chrome.extension.getURL('images/ic_create_black_48px.svg')}" width=16 height=16/>
              </button>
            </span>`;

        const encryptionForm =
            `<form class="form-inline position-abs-right">
              <input type="password" class="gCrypt-password-input" placeholder="password" id="gCryptPasswordEncrypt">
            </form>`;

        $(this).closest('div').prepend(encryptionForm);
        $(this).closest('div').css('height', 'inherit');
        $(`<td class="gU" style="min-width: 75px">${encryptionFormOptions}</td>`).insertAfter($(this).find('>:first-child'));
        composeMenu.find('#encryptAndSign').click({ action: 'encryptAndSign' }, sendAndHandleBackgroundCall);
        composeMenu.find('#encrypt').click({ action: 'encrypt' }, sendAndHandleBackgroundCall);
        composeMenu.find('#sign').click({ action: 'sign' }, sendAndHandleBackgroundCall);
        composeMenu.find('form[class="form-inline"]').submit({ action: 'encryptAndSign' }, function (event) {
          sendAndHandleBackgroundCall(event);
          return false;
        });
      }
    });
    sendExtensionRequestPromise({ method: 'getOption', option: 'mymail-stopAutomaticDrafts' })
    .then(function (response) {
      if (response === true) {
        stopAutomaticDrafts();
      }
    });
  }

  const viewTitleBar = rootElement.find('td[class="gH acX"]');
  if (viewTitleBar && viewTitleBar.length > 0) {
    viewTitleBar.each(function () {
      const BUTTON_GROUP_CLASS = 'gCrypt-decrypt-button-group';
      if ($(this).find(`.${BUTTON_GROUP_CLASS}`).length === 0) {
        $(this).prepend(`<div style="display:inline-flex"><div class="${BUTTON_GROUP_CLASS}">`);
        const buttonGroup = $(this).find(`.${BUTTON_GROUP_CLASS}`);
        buttonGroup.prepend(`<button class="" action="decrypt" id="decrypt"><img src="${chrome.extension.getURL('images/ic_lock_open_black_24px.svg')}" width=16 height=16 />Decrypt</button></span>`);
        buttonGroup.find('#decrypt').click({ action: 'decrypt' }, sendAndHandleDecryptAndVerify);
        buttonGroup.append('<form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordDecrypt"></form>');
        buttonGroup.find('form[class="form-inline"]').submit(function () {
          buttonGroup.parent().find('a[action="decrypt"]').click();
          return false;
        });
        buttonGroup.prepend('<button class="" id="verify">Verify Signature</button>');
        buttonGroup.find('#verify').click({ action: 'verify' }, sendAndHandleDecryptAndVerify);
      }
    });
  }
}

// This animation strategy inspired by http://blog.streak.com/2012/11/how-to-detect-dom-changes-in-css.html
// based on http://davidwalsh.name/detect-node-insertion changes will depend on CSS as well.
const insertListener = function (event) {
  if (event.animationName === 'composeInserted') {
    composeIntercept();
  }
};

// TODO this used to be more reliable to call the eventlistener in $(document).ready idk why it's not now
// $(document).ready(onLoadAnimation);
document.addEventListener('webkitAnimationStart', insertListener, false);
