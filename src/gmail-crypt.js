/* This is the general class for gmail-crypt that runs within gmail context.
 *
 * Copyright 2011 - 2013 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */

 

(function(rootElemnt) {
    var self = this;

    var useComposeSubWindows = false;
	
	$('body').append('<div id="gCryptModal" class="modal fade" tabindex="-1" role="dialog" aria-labelledby="gCryptModalLabel" aria-hidden="true">' +
		'<div class="modal-dialog"><div class="modal-content">' +
		'<div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button><h4 id="gCryptModalLabel" class="modal-title"></h4></div>' +
		'<div class="modal-body"><p class="modal-body-content"></p></div>' +
		'<div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Close</button></div>' +
		'</div></div></div>');
	var $alertModal = $('#gCryptModal');
	
    this.showAlert = function(title, body) {
		$alertModal.find('.modal-title').text(title);
		$alertModal.find('.modal-body-content').text(body);
		$alertModal.modal({show: true, keyboard: true});
    };

    //This clear and save is specific to the embedded reply composes
    this.clearAndSaveReply = function(event) {
		rootElement.find('[class*="gA gt"] [g_editable]').html('');
		var replyForm = rootElement.find('[class*="gA gt"] form[method="POST"]');
		replyForm.attr('id', replyForm.attr('old-id'));
		$(event.target).find('a').click();
		return true;
    };

    this.clearAndSave = function(event) {
		//Find the related compose box, and blank out, then proceed as if normal closing.
		//TODO could probably clean this up to be more DRY
		$(event.target).parents('[class="I5"]').find('[g_editable]').html('');
		self.saveDraft(event);
    };

    this.saveDraft = function(event) {
		var form = $(event.target).parents('[class="I5"]').find('form[method="POST"]');
		form.attr('id', form.attr('old-id'));
		return true;
    };

    this.rebindSendButtons = function() {
		var sendButtons = rootElement.find('td[class="gU Up"] > div > [role="button"]');
		sendButtons.mousedown(saveDraft);

		var closeComposeButtons = rootElement.find('[class="Ha"]');
		closeComposeButtons.mousedown(clearAndSave);

		if (rootElement.find('[class*="gA gt"]')) {
			rootElement.find('.oo').click(clearAndSaveReply);
			rootElement.find('.adf').click(clearAndSaveReply);
		}
    };

    this.getContents = function(form, event) {
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
        
		try {
            msg = iframe.html().replace(/(<div>)/g,'\n');
            msg = msg.replace(/(<\/div>)/g,'');
        }
        catch(e){
            msg = textarea.val();
        }
		
        return {textarea: textarea, iframe: iframe, msg: msg };
    };

    //This could be streamlined as google has change this mechanism frequently.
    this.writeContents = function(contents, message) {
        if (contents.g_editable) {
            message = message.split('\n').join('<br/>');
            contents.g_editable.html(message);
        } 
		
		try {
            contents.iframe[0].innerText = message;
        } catch(e) {
			//No iframe (rich editor) entry, only plaintext loaded
        } 
		
		try {
            contents.textarea.val(message);
        } catch(e) {
			//No plaintext editor
        }
    };

    this.getRecipients = function(event) {
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
		} else {
			//for new-old style			
			$(event.target).closest('.nH.Hd, .aoI').find('.vN.Y7BVp').each(function() {
				recipients.email.push(gCryptUtil.parseUser($(this).attr('email')).userEmail);
			});
			
			if (recipients.email.length == 0) {
				// for old-old style
				$(event.target).closest('.nH.Hd, .aoI').find('.vN.vP').each(function() {
					recipients.email.push(gCryptUtil.parseUser($(this).attr('email')).userEmail);
				});
			}
		} 
		
		var s = 'modfied finding recepits for old gmail';
		
		return recipients;
    };

    this.encryptAndSign = function(event) {
		var form = rootElement.find('form');
		var contents = getContents(form, event);
		var privKey;
		var recipients = getRecipients(event);
		
		passwordStore.get(function(password) {		
			chrome.extension.sendRequest({method: "encryptAndSign", recipients: recipients, message: contents.msg, password: password}, function(response){
				if(response && response.type && response.type == "error") {
					self.showAlert('Error', response.text);
					return;
				}
				self.writeContents(contents, response);
				$('#encrypt-sign-icon', event.target).attr('src', chrome.extension.getURL("images/encrypt_sign_closed.png"));
			});
		}
		, function(password, callback) {
			chrome.extension.sendRequest({method: "verifyPassword", password: password}, function(response){
				if(response && response.type && response.type == "error") {
					callback(response.text);
				} else {
					callback(true);
				}
			});
			// we need to return null as sendRequest is async so we will have to use the callback for the passwordStore
			return null;		
		});
    };

    this.sign = function(event) {
		var form = rootElement.find('form');
		form.find('.alert').hide();
		var contents = self.getContents(form, event);
		
		passwordStore.get(function(password) {
			chrome.extension.sendRequest({method: "sign", message: contents.msg, password: password}, function(response){
				if(response && response.type && response.type == "error") {
					self.showAlert('Error', response.text);
					return;
				}
				self.writeContents(contents, response);
				$('#sign-icon', event.target).attr('src', chrome.extension.getURL("images/sign_closed.png"));
			});
		} 
		, function(password, callback) {
			chrome.extension.sendRequest({method: "verifyPassword", password: password}, function(response){
				if(response && response.type && response.type == "error") {
					callback(response.text);
				} else {
					callback(true);
				}
			});
			// we need to return null as sendRequest is async so we will have to use the callback for the passwordStore
			return null;		
		});
    };
	
    this.encrypt = function(event) {
		var form = rootElement.find('form');
		form.find('.alert').hide();
		var contents = self.getContents(form, event);
		var recipients = self.getRecipients(event);

		chrome.extension.sendRequest({method: "encrypt", recipients: recipients, message: contents.msg}, function(response) {
			if(response && response.type && response.type == "error") {
				self.showAlert('Error', response.text);
				return;
			}
			self.writeContents(contents, response);
			$('#encrypt-icon', event.target).attr('src', chrome.extension.getURL("images/encrypt_closed.png"));
		});
    };


    this.getMessage = function(objectContext) {
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

    this.decrypt = function(event) {
		var objectContext = this;
		var setup = self.getMessage(objectContext);
		var element = setup[0];
		var msg = setup[1];
		var senderEmail = $(objectContext).parents('div[class="gE iv gt"]').find('span [email]').attr('email');
	
		passwordStore.get(function(password) {
			chrome.extension.sendRequest({method: "decrypt", senderEmail:senderEmail, msg: msg, password: password}, function(response){
				$.each(response.status, function(key, status) {
					$(objectContext).parents('div[class="gE iv gt"]').append(status.html);
				});
				
				if (response.decrypted) {
					element.html(response.text.replace(/\n/g,'<br>'));
					$('#decrypt-icon').attr('src', chrome.extension.getURL("images/encrypt_open.png"));
				} else {
					self.showAlert('Error', 'There was an unexpected error decrypting your message');
				}
			});
		}
		, function(password, callback) {
			chrome.extension.sendRequest({method: "verifyPassword", password: password}, function(response){
				if(response && response.type && response.type == "error") {
					callback(response.text);
				} else {
					callback(true);
				}
			});
			// we need to return null as sendRequest is async so we will have to use the callback for the passwordStore
			return null;		
		});
    };

    //TODO: this has not yet been completed in openpgp.js
    this.verifySignature = function() {
        var setup = self.getMessage(this);
        var msg = setup[1];
        var form = rootElement.find('form');
        var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
        var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
    };

    this.stopAutomaticDrafts = function() {
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


    this.composeIntercept = function(ev) {
        var composeBoxes = $('.n1tfz');
        if (composeBoxes && composeBoxes.length > 0) {
			composeBoxes.each(function() {
				if ($(this).find('.encrypt-compose-btn').length === 0) {
					var attach = $('.gU.az5', this);
					attach.before('<td class="encrypt-compose-btn oc gU">' +
								  '<div data-tooltip="Encrypt" aria-label="Encrypt">' +
								  '<div id="encrypt" class="J-J5-Ji J-Z-I-Kv-H" aria-pressed="false" role="button" aria-haspopup="false" aria-expanded="false" style="-webkit-user-select: none;">' +
								  '<div class="J-J5-Ji J-Z-I-Kv-H"><div class="J-J5-Ji J-Z-I-J6-H">' +
								  '<img id="encrypt-icon" src="'+chrome.extension.getURL("images/encrypt_open.png")+'" width=13 height=13/></span></div></div></div></div></td>');
					attach.before('<td class="encrypt-sign-compose-btn oc gU">' +
								  '<div data-tooltip="Encrypt and sign" aria-label="Encrypt and sign">' +
								  '<div id="encrypt-sign" class="J-J5-Ji J-Z-I-Kv-H" aria-pressed="false" role="button" aria-haspopup="false" aria-expanded="false" style="-webkit-user-select: none;">' +
								  '<div class="J-J5-Ji J-Z-I-Kv-H"><div class="J-J5-Ji J-Z-I-J6-H">' +
								  '<img id="encrypt-sign-icon" src="'+chrome.extension.getURL("images/encrypt_sign_open.png")+'" width=13 height=13/></span></div></div></div></div></td>');
					attach.before('<td class="oc gU sign-compose-btn">' +
								  '<div data-tooltip="Sign" aria-label="Sign">' +
								  '<div id="sign" class="J-J5-Ji J-Z-I-Kv-H" aria-pressed="false" role="button" aria-haspopup="false" aria-expanded="false" style="-webkit-user-select: none;">' +
								  '<div class="J-J5-Ji J-Z-I-Kv-H"><div class="J-J5-Ji J-Z-I-J6-H">' +
								  '<img id="sign-icon" src="'+chrome.extension.getURL("images/sign_open.png")+'" width=13 height=13/></span></div></div></div></div></td>');
					attach.before('<td class="gU"><div class="Uz"></div></td>');
					
					$('.encrypt-compose-btn', this).on('click', self.encrypt);
					$('.encrypt-sign-compose-btn', this).on('click', self.encryptAndSign);
					$('.sign-compose-btn', this).on('click', self.sign);
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
                menubar.append('<span id="gCryptEncrypt" class="btn-group"><a class="btn" href="#" id="encryptAndSign1">' +
					'<img src="'+chrome.extension.getURL("images/encrypt_closed.png")+'" width=13 height=13/> Encrypt</a>' +
					'<a class="btn dropdown-toggle" data-toggle="dropdown" href="#"><span class="caret"></span></a>'  +
					'<ul class="dropdown-menu"><li id="encryptAndSign2"><a href="#">Encrypt (sign)</a></li><li id="encrypt">' +
					'<a href="#">Encrypt (don\'t sign)</a></li><li id="sign"><a href="#">Sign only</a></li></ul></span>');
                menubar.find('#encryptAndSign1').click(self.encryptAndSign);
                menubar.find('#encryptAndSign2').click(self.encryptAndSign);
                menubar.find('#encrypt').click(self.encrypt);
                menubar.find('#sign').click(self.sign);

            }
        };

        //Why is this not firing for all cases? It seems that if a page has been previously loaded it uses some sort of caching and won't fire the event
        var viewTitleBar = rootElement.find('td[class="gH acX"]');
        if(viewTitleBar && viewTitleBar.length > 0){
            viewTitleBar.each(function(v) {
				$this = $(this);
                if($this.find('#decrypt-div').length === 0){      
					$this.prepend(
						'<div id="decrypt-div" class="T-I J-J5-Ji T-I-Js-IF aaq T-I-ax7 L3" role="button" tabindex="0" data-tooltip="Decrypt" aria-label="Decrypt" style="-webkit-user-select: none;">' +
						'<img id="decrypt-icon" class="gc-decrypt-icon T-I-J3" role="button" src="' +chrome.extension.getURL("images/encrypt_closed.png")+ '" alt=""></div>');
                    $this.find('#decrypt-div').click(self.decrypt);
                    //TODO: <a class="btn" href="#" id="verifySignature">Check Signature</a>
                    //$(this).find('#verifySignature').click(verifySignature);
                }
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
	
        document.addEventListener("webkitAnimationStart", self.insertListener, false);
        openpgp.init();
        chrome.extension.sendRequest({method: 'getConfig'}, function(response){
			openpgp.config = response;
			passwordStore.password_timeout = openpgp.config.password_timeout;
        });
    };

    this.init = function() {
        $(document).ready(this.onLoadAnimation);
    };
	
	/**
	  * The passwordStore contains methods to get a password, and will then store the password for a configurable period of time, or
	  * can be manually invalidated.
	  */
	 var passwordStore = (function() {
		var password = null;
		/** interval id used to set the timeout for the password */
		var inter = null;
		
		/** String that contains the html for the password modal */
		var modalstr = '<div class="modal fade"><div class="modal-dialog"><div class="modal-content">' +
			'<div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button></div>' +
			'<div class="modal-body">' +
			'<div class="form-group">' +
			'<label for="password">Password</label>' +
			'<input type="password" class="form-control" name="password" placeholder="Enter password">' +
			'</div></div>' +
			'<div class="modal-footer">' +
			'<button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>' +
			'<button type="button" class="btn btn-primary">Enter</button>' +
			'</div></div></div></div>';
			
		// default of 5 min timeout
		this.password_timeout = 5;
			
		/**
		 * Shows a dialog to enter a password, and using a callback to verify the password and display an error if required
		 * @param {function} [passwordCallback] Called when a valid password has been entered, takes the form function(password)
		 * @param {function} [verifyCallback] Called to validate the entered password, can be used asynchronously or synchronously. If 
		 * it returns a string then this is used as an error message, or true to signify a valid password. verifyCallback is called with the password
		 * and a callback that can be used to verify the password. The callback takes the form function(verified) where verified === true for a password
		 * or a string error message if not. verifyCallback takes the form function(password, function(verified))
		 */
		this.get = function(passwordCallback, verifyCallback, originalError) {
			
			if (password) {
				var verified = verifyCallback(password, function(verified) {
					// Handle this being called async
					if (verified === true) {
						resetInvalidateTime();
						passwordCallback(newPassword);
					} else if (typeof(verified) == 'string') {
						get(passwordCallback, verifyCallback, verified);
					}
					return;
				});
				
				if (verified === true) {
					resetInvalidateTime();
					passwordCallback(newPassword);
				} else if (typeof(verified) == 'string') {
					get(passwordCallback, verifyCallback, verified);
				}
				
				return;
			}
			
			// Create a modal from our string, bind keypress and click handlers and show it.
			var $modal = $(modalstr);
			
			if (originalError && typeof(originalError) == 'string') {
				$modal.find('.modal-body .form-group').before('<p class="text-danger">' + originalError + '</p>');
			}
			
			$modal.find('input[name="password"]').keypress(function(ev) {
				if (ev.which == 13) {
					verify($modal, ev.target.value, passwordCallback, verifyCallback);
				}
			});
			
			$modal.find('button.btn-primary').click(function(ev) {
				$modal.find('.text-danger').remove();
				
				var newPassword = $modal.find('input[name="password"]').val();
				verify($modal, newPassword, passwordCallback, verifyCallback);
			});
			
			$modal.find('button.btn-default').click(function(ev) {
				delete $modal;
			});
			
			$modal.modal({
				show: true,
				keyboard: false
			});
			
			$modal.find('input[type="password"]').focus();
		};
		
		var verify = function($modal, newPassword, passwordCallback, verifyCallback) {
			$modal.find('.text-danger').remove();
				
			if (newPassword == '') {
				$modal.find('.form-group').addClass('has-warning');
			} else {
				var verified = verifyCallback(newPassword, function(verified) {
					// Handle this being called async
					if (verified === true) {
						$modal.modal('hide');
						password = newPassword;
						resetInvalidateTime();
						passwordCallback(newPassword);
						delete $modal;
					} else if (typeof(verified) == 'string') {
						$modal.find('.modal-body .form-group').before('<p class="text-danger">' + verified + '</p>');
						$modal.find('.form-group').addClass('has-warning');
					}
					return;
				});
				
				if (verified === true) {
					$modal.modal('hide');
					password = newPassword;
					resetInvalidateTime();
					passwordCallback(newPassword);
					delete $modal;
				} else if (typeof(verified) == 'string') {
					$modal.find('.modal-body .form-group').before('<p class="text-danger">' + verified + '</p>');
					$modal.find('.form-group').addClass('has-warning');
				}
			}
		};
		
		var resetInvalidateTime = function() {
			if (inter) {
				clearInterval(inter);
			}
			
			inter = setInterval(function() {
				password = null;		
				clearInterval(inter);
				inter = null;
			}, 1000 * 60 * this.password_timeout);	
		};
		
		// Invalidates the stored password (if there is one)
		this.invalidate = function() {
			password = null;
			if (inter) {
				clearInterval(inter);
			}
		};
		
		return this;
	 })();
	
	return this;
})($(document)).init();

