/* This is the general class for gmail-crypt that runs within gmail context.
 *
 * Copyright 2011 - 2013 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */


(function(rootElemnt) {
    var self = this;

    var useComposeSubWindows = false;

    this.showMessages = function(str){
          console.log(str);
    };

    //This clear and save is specific to the embedded reply composes
    this.clearAndSaveReply = function(event){
      rootElement.find('[class*="gA gt"] [g_editable]').html('');
      var replyForm = rootElement.find('[class*="gA gt"] form[method="POST"]');
      replyForm.attr('id', replyForm.attr('old-id'));
      $(event.target).find('a').click();
      return true;
    };

    this.clearAndSave = function(event){
      //Find the related compose box, and blank out, then proceed as if normal closing.
      //TODO could probably clean this up to be more DRY
      $(event.target).parents('[class="I5"]').find('[g_editable]').html('');
      self.saveDraft(event);
    };

    this.saveDraft = function(event){
      var form = $(event.target).parents('[class="I5"]').find('form[method="POST"]');
      form.attr('id', form.attr('old-id'));
      return true;
    };

    this.rebindSendButtons = function(){
      var sendButtons = rootElement.find('td[class="gU Up"] > div > [role="button"]');
      sendButtons.mousedown(saveDraft);

      var closeComposeButtons = rootElement.find('[class="Ha"]');
      closeComposeButtons.mousedown(clearAndSave);

      if (rootElement.find('[class*="gA gt"]')) {
        rootElement.find('.oo').click(clearAndSaveReply);
        rootElement.find('.adf').click(clearAndSaveReply);
      }
    };

    this.getContents = function(form, event){
        //g_editable is intended to work with Gmail's new broken out window approach.
        //we search based on event because it works well in case multiple compose windows are open
        var msg;
        var g_editable = $(event.currentTarget).parents().find('[g_editable]').first();
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
    };

    //This could be streamlined as google has change this mechanism frequently.
    this.writeContents = function(contents, message){
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
    };

    this.getRecipients = function(form, event){
      var recipients = {};
      recipients.email = [];
      if (useComposeSubWindows) {
        //for new in window compose gmail window
        var emailsParent = $(event.currentTarget).parents().find('[email]').last().parent().parent();
        if (emailsParent && emailsParent.length > 0) {
          emailsParent.find('[email]').each(function() {
            recipients.email.push($(this).attr("email"));
          });
        }
      }
      else {
        //for old style
        var to = form.find('textarea[name="to"]').val().split(',').concat(form.find('textarea[name="cc"]').val().split(','));
        for(var recipient in to){
          if(to[recipient].length > 2) {
            recipients.email.push(gCryptUtil.parseUser(to[recipient]).userEmail);
          }
        }
      }
      return recipients;
    };

    this.encryptAndSign = function(event){
      var form = rootElement.find('form');
      form.find('.alert').hide();
      var contents = getContents(form, event);
      var privKey;
      var password = rootElement.find('#gCryptPasswordEncrypt').val();
      var recipients = getRecipients(form, event);
      chrome.extension.sendRequest({method: "encryptAndSign", recipients: recipients, message: contents.msg, password: password}, function(response){
        if(response && response.type && response.type == "error") {
          self.showAlert(response, form);
        }
        self.writeContents(contents, response);
      });
    };

    this.encrypt = function(event){
      var form = rootElement.find('form');
      form.find('.alert').hide();
      var contents = self.getContents(form, event);
      var recipients = self.getRecipients(form, event);

      chrome.extension.sendRequest({method: "encrypt", recipients: recipients, message: contents.msg}, function(response){
        if(response && response.type && response.type == "error") {
          self.showAlert(response, form);
        }
        self.writeContents(contents, response);
      });
    };

    this.sign = function(event){
      var form = rootElement.find('form');
      form.find('.alert').hide();
      var contents = self.getContents(form, event);
      var password = rootElement.find('#gCryptPasswordEncrypt').val();

      chrome.extension.sendRequest({method: "sign", message: contents.msg, password: password}, function(response){
        if(response && response.type && response.type == "error") {
          self.showAlert(response, form);
        }
        self.writeContents(contents, response);
      });
    }l

    this.getMessage = function(objectContext){
      var msg;
      //we need to use regex here because gmail will automatically form \n into <br> or <wbr>, strip these out
      //I'm not entirely happy with these replace statements, perhaps there can be a different approach
      element = $(event.currentTarget).closest('div[class="gs"]').find('[class*="ii gt"] div');
      msg = element.html().replace(/\n/g,"");
      msg = msg.replace(/(<br><\/div>)/g,'\n'); //we need to ensure that extra spaces aren't added where gmail puts a <div><br></div>
      msg = msg.replace(/(<\/div>)/g,'\n');
      msg = msg.replace(/(<br>)/g,'\n');

      //originally stripped just <br> and <wbr> but gmail can add other things such as <div class="im">
      msg = msg.replace(/<(.*?)>/g,'');
      return [element, msg];
    };

    this.decrypt = function(event){
      var password = $(this).parent().parent().find('form[class="form-inline"] input[type="password"]').val();
      rootElement.find('.alert').hide();
      var objectContext = this;
      var setup = self.getMessage(objectContext);
      var element = setup[0];
      var msg = setup[1];
      var senderEmail = $(objectContext).parents('div[class="gE iv gt"]').find('span [email]').attr('email');
      chrome.extension.sendRequest({method: "decrypt", senderEmail:senderEmail, msg: msg, password: password}, function(response){
        $.each(response.status, function(key, status) {
          $(objectContext).parents('div[class="gE iv gt"]').append(status.html);
        });
        if (response.decrypted) {
          element.html(response.text.replace(/\n/g,'<br>'));
        }
      });
    };

    //TODO: this has not yet been completed in openpgp.js
    this.verifySignature = function(){
        var setup = self.getMessage(this);
        var msg = setup[1];
        var form = rootElement.find('form');
        var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
        var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
    };

    this.stopAutomaticDrafts = function(){
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

      self.rebindSendButtons();
      //setTimeout here because we need to check if new windows are opened
      setTimeout(self.stopAutomaticDrafts, 2000);
    };

    this.showAlert = function(alert, form) {
        if(form) {
            var alertInForm = form.find('#'+alert.id);
            if (alertInForm && alertInForm.length > 0) {
                alertInForm.show();
                return;
            }
        }
        self.showModalAlert(alert.html);
    };

    this.showModalAlert = function(message) {
      $('#gCryptModalBody').html(message);
      $('#gCryptModal').modal('show');
    };

    this.composeIntercept = function(ev) {
        var composeBoxes = $('.n1tfz');
        if (composeBoxes && composeBoxes.length > 0) {
            composeBoxes.each(function(){
                var composeMenu = $(this).parent().parent().parent();
                if (composeMenu && composeMenu.length> 0 && composeMenu.find('#gCryptEncrypt').length === 0) {
                    useComposeSubWindows = true;
                    var maxSizeCheck = composeMenu.parent().parent().parent().parent().parent().find('[style*="max-height"]');
                    //We have to check again because of rapidly changing elements
                    if(composeMenu.find('#gCryptEncrypt').length === 0) {
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
                        composeMenu.find('#encryptAndSign').click(encryptAndSign);
                        composeMenu.find('#encrypt').click(encrypt);
                        composeMenu.find('#sign').click(sign);
                        composeMenu.find('form[class="form-inline"]').submit(function(event){
                            encryptAndSign(event);
                            return false;
                        });
                    }
                }
            });
            chrome.extension.sendRequest({method: 'getOption', option: 'stopAutomaticDrafts'}, function(response){
              if(response === true){
                self.stopAutomaticDrafts();
              }
            });
        }
        rootElement = $('#canvas_frame').length > 0 ? $('#canvas_frame').contents() : $(document);
        var form = rootElement.find('form');
        var menubar = form.find('td[class="fA"]');
        if(menubar && menubar.length>0){
            if(menubar.find('#gCryptEncrypt').length === 0){
                menubar.append('<span id="gCryptEncrypt" class="btn-group"><a class="btn" href="#" id="encryptAndSign1"><img src="'+chrome.extension.getURL("images/encryptIcon.png")+'" width=13 height=13/> Encrypt</a><a class="btn dropdown-toggle" data-toggle="dropdown" href="#"><span class="caret"></span></a><ul class="dropdown-menu"><li id="encryptAndSign2"><a href="#">Encrypt (sign)</a></li><li id="encrypt"><a href="#">Encrypt (don\'t sign)</a></li><li id="sign"><a href="#">Sign only</a></li></ul></span><form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordEncrypt"></form>');
                menubar.find('#encryptAndSign1').click(encryptAndSign);
                menubar.find('#encryptAndSign2').click(encryptAndSign);
                menubar.find('#encrypt').click(encrypt);
                menubar.find('#sign').click(sign);
                menubar.find('form[class="form-inline"]').submit(function(event){
                    self.encryptAndSign(event);
                    return false;
                });

            }
        };

        //Why is this not firing for all cases? It seems that if a page has been previously loaded it uses some sort of caching and won't fire the event
        var viewTitleBar = rootElement.find('td[class="gH acX"]');
        if(viewTitleBar && viewTitleBar.length > 0){
            viewTitleBar.each(function(v){
                if( $(this).find('#gCryptDecrypt').length === 0){
                    $(this).prepend('<span id="gCryptDecrypt"><a class="btn" href="#" id="decrypt"><img src="'+chrome.extension.getURL("images/decryptIcon.png")+'" width=13 height=13/ >Decrypt</a></span>');
                    $(this).find('#decrypt').click(decrypt);
                    $(this).append('<form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordDecrypt"></form>');
                    $(this).find('form[class="form-inline"]').submit(function(event){
                        $(this).parent().find('a[class="btn"]').click();
                        return false;
                    });
                    //TODO: <a class="btn" href="#" id="verifySignature">Check Signature</a>
                    //$(this).find('#verifySignature').click(verifySignature);
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
    };

    //This animation strategy inspired by http://blog.streak.com/2012/11/how-to-detect-dom-changes-in-css.html
    //based on http://davidwalsh.name/detect-node-insertion changes will depend on CSS as well.
    this.insertListener = function(event) {
      if (event.animationName == "composeInserted") {
        self.composeIntercept();
      }
    };

    this.onLoadAnimation = function() {
        document.addEventListener("webkitAnimationStart", this.insertListener, false);
        openpgp.init();
        chrome.extension.sendRequest({method: 'getConfig'}, function(response){
          openpgp.config = response;
        });
    };

    this.init = function() {
        $(document).ready(this.onLoadAnimation);
    };
})($(document)).init();

