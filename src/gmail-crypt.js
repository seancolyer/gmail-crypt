/* This is the general class for gmail-crypt that runs within gmail context. 
 * 
 * Copyright 2011,2012 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2. 
 * See included "LICENSE" file for details.
 */

var menubarLoaded = false;
var viewTitleBarLoaded = false;
//gmailVersion was added with the new role out ~11/3/11 of the new gmail style. Value 1 is for old style, 2 is for new.
var gmailVersion = 0;
var openpgpLog;

function showMessages(str){
openpgpLog += str;
}

function getContents(form){
    var textarea = $('textarea[name="body"]',form);
    var iframe = $('iframe',form).contents().find('body');
    var msg;
    try{
        msg = iframe.html().replace(/(<div>)/g,'\n');
        msg = msg.replace(/(<\/div>)/g,'');
    }
    catch(e){
        msg = textarea.val();
    }
    return {textarea: textarea, iframe: iframe, msg: msg };
}

function writeContents(contents, message){
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

function getRecipients(form){
    var to = form.find('textarea[name="to"]').val().split(',').concat(form.find('textarea[name="cc"]').val().split(','));
    var recipients = [];
    for(var recipient in to){
        if(to[recipient].length > 0)
            recipients.push(gCryptUtil.parseUser(to[recipient]).userEmail);
        }
    return recipients;
        
}

function encryptAndSign(){
    var form = $('#canvas_frame').contents().find('form');
    form.find('.alert-error').hide();
    var contents = getContents(form);
	var privKey;
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        privKey = openpgp.read_privateKey(response[0].armored)[0];
        if(!privKey.decryptSecretMPIs()){
            var password = $('#canvas_frame').contents().find('#gCryptPasswordEncrypt').val();
            if(!privKey.decryptSecretMPIs(password))
                form.find('#gCryptAlertPassword').show();
        }
        var recipients = getRecipients(form);
        if(recipients.length == 0){
            form.find('#gCryptAlertEncryptNoUser').show();
            return;        
        }
        chrome.extension.sendRequest({method: "getPublicKeys",emails:recipients}, function(response){
            var publicKeys = [];
            for(var recipient in response){
                if(response[recipient].length == 0)
                    form.find('#gCryptAlertEncryptNoUser').show();
                else{
                    publicKeys.push(openpgp.read_publicKey(response[recipient])[0]);
                }
            }
            var ciphertext = openpgp.write_signed_and_encrypted_message(privKey,publicKeys,contents.msg);
            writeContents(contents, ciphertext);
            });
        });
}

function encrypt(){
    var form = $('#canvas_frame').contents().find('form');
    form.find('.alert-error').hide();
    var contents = getContents(form);
    
    var recipients = getRecipients(form);
    if(recipients.length == 0){
        form.find('#gCryptAlertEncryptNoUser').show();
        return;        
    }
    chrome.extension.sendRequest({method: "getPublicKeys",emails:recipients}, function(response){
        var publicKeys = [];
        for(var recipient in response){
            if(response[recipient].length == 0)
                form.find('#gCryptAlertEncryptNoUser').show();
            else{
                publicKeys.push(openpgp.read_publicKey(response[recipient])[0]);
            }
        }
        var ciphertext = openpgp.write_encrypted_message(publicKeys,contents.msg);
        writeContents(contents, ciphertext);
        });
}

function sign(){
    var form = $('#canvas_frame').contents().find('form');
    form.find('.alert-error').hide();
    var contents = getContents(form);
	var privKey;
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        privKey = openpgp.read_privateKey(response[0].armored)[0];
        if(!privKey.decryptSecretMPIs()){
            var password = $('#canvas_frame').contents().find('#gCryptPasswordEncrypt').val();
            if(!privKey.decryptSecretMPIs(password))
                form.find('#gCryptAlertPassword').show();
        }
        var ciphertext = openpgp.write_signed_message(privKey,contents.msg);
        writeContents(contents,ciphertext);
        });
}

function getMessage(objectContext){
    var msg;
    //we need to use regex here because gmail will automatically form \n into <br> or <wbr>, strip these out
    //I'm not entirely happy with these replace statements, perhaps there can be a different approach
    if(gmailVersion == 1){
        element = $(event.currentTarget).closest('[class="G3 G2"]').find('[class="ii gt"] div');
        msg = element.html().replace(/(<br>)|(<wbr>)/g,'\n');
    }
    if(gmailVersion == 2){
        element = $(event.currentTarget).closest('div[class="gs"]').find('[class*="ii gt"] div');
        msg = element.html().replace(/\n/g,"");
        msg = msg.replace(/(<br><\/div>)/g,'\n'); //we need to ensure that extra spaces aren't added where gmail puts a <div><br></div>
        msg = msg.replace(/(<\/div>)/g,'\n');
        msg = msg.replace(/(<br>)/g,'\n');
    }
    
    //originally stripped just <br> and <wbr> but gmail can add other things such as <div class="im">
    msg = msg.replace(/<(.*?)>/g,'');
    msg = openpgp.read_message(msg);
    if(msg == null){
        $(objectContext).parents('div[class="gE iv gt"]').append('<div class="alert alert-error" id="gCryptAlertDecryptNoMessage">No OpenPGP message was found.</div>');
        return;
    }
    return [element, msg[0]];

}

function decrypt(event){
    var password = $(this).parent().parent().find('form[class="form-inline"] input[type="password"]').val();
    $('#canvas_frame').contents().find('.alert-error').hide();
    var objectContext = this;
    var setup = getMessage(objectContext);
    var element = setup[0];
    var msg = setup[1];
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        for(var r = 0; r<response.length;r++){
            var key = openpgp.read_privateKey(response[r].armored)[0];
            if(!key.decryptSecretMPIs()){
                if(!key.decryptSecretMPIs(password))
               	    $(objectContext).parents('div[class="gE iv gt"]').append('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt For Gmail was unable to read your key. Is your password correct?</div>');
            }
            var material = {key: key , keymaterial: key.privateKeyPacket};
            for(var sessionKeyIterator in msg.sessionKeys){
                var sessionKey = msg.sessionKeys[sessionKeyIterator];
                try{
                    var text = msg.decrypt(material, sessionKey);
                    
                    if(text != ''){
                        element.html(text.replace(/\n/g,'<br>'));
                        return;
                        }
                    }
                catch(e){ //This means that the initial key is not the one we need
                }
			    for (var j = 0; j < key.subKeys.length; j++) {
				    keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
				    sesskey = msg[0].sessionKeys[i];
				    try{
                        text = msg.decrypt(material, sessionKey);
                        if(text != ''){
                            element.html(text.replace(/\n/g,'<br>'));
                            return;
                            }
            		}
        		    catch(e){
        		    //Current key is not the correct key
        		    }
        		    }
                }
            }
        $(objectContext).parents('div[class="gE iv gt"]').append('<div class="alert alert-error" id="gCryptAlertDecrypt">Mymail-Crypt for Gmail was unable to decrypt this message. </div>');
        });
    }

//TODO: this has not yet been completed in openpgp.js
function verifySignature(){
    var setup = getMessage(this);
    var msg = setup[1];
    var form = $('#canvas_frame').contents().find('form');
    var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
    var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
    //TODO: this should be updated to only query for certain public keys
    chrome.extension.sendRequest({method: "getAllPublicKeys"}, function(response){
        for(var r = 0; r < response.length; r++){
            var pubKey = openpgp.read_publicKey(response[r].armored);
            //openpgp.verifySignature();
            }
        });
    }

function composeIntercept(ev) {
    if( $('#canvas_frame').contents().find('html[class="cQ"]').length > 0)
        gmailVersion = 1;
    if( $('#canvas_frame').contents().find('html[class="aao"]').length > 0){
        gmailVersion = 2;
        }

	var form = $('#canvas_frame').contents().find('form');
    var menubar = form.find('td[class="fA"]');
	if(menubar.length>0){
        if(menubar.find('#gCryptEncrypt').length == 0){
            menubar.append('<span id="gCryptEncrypt" class="btn-group"><a class="btn" href="#" id="encryptAndSign1"><img src="'+chrome.extension.getURL("images/encryptIcon.png")+'" width=13 height=13/> Encrypt</a><a class="btn dropdown-toggle" data-toggle="dropdown" href="#"><span class="caret"></span></a><ul class="dropdown-menu"><li id="encryptAndSign2"><a href="#">Encrypt (sign)</a></li><li id="encrypt"><a href="#">Encrypt (don\'t sign)</a></li><li id="sign"><a href="#">Sign only</a></li></ul></span><form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordEncrypt"></form>');
            menubar.find('#encryptAndSign1').click(encryptAndSign);
            menubar.find('#encryptAndSign2').click(encryptAndSign);
            menubar.find('#encrypt').click(encrypt);
            menubar.find('#sign').click(sign);
            menubar.find('form[class="form-inline"]').submit(function(){
                encryptAndSign();
                return false;
            });
            form.find('.eJ').append('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt for Gmail was unable to read your key. Is your password correct?</div>');
            form.find('.eJ').append('<div class="alert alert-error" id="gCryptAlertEncryptNoUser">Unable to find a key for the given user. Have you inserted their public key?</div>');
        }
	}
	
	//Why is this not firing for all cases? It seems that if a page has been previously loaded it uses some sort of caching and won't fire the event
	var viewTitleBar;
	if(gmailVersion == 1)
	    viewTitleBar = $('#canvas_frame').contents().find('div[class="G0"]');
	if(gmailVersion == 2){
	    viewTitleBar = $('#canvas_frame').contents().find('td[class="gH acX"]');
	}
    if(viewTitleBar.length > 0){
        viewTitleBar.each(function(v){
            if( $(this).find('#gCryptDecrypt').length == 0){
	            $(this).prepend('<span id="gCryptDecrypt"><a class="btn" href="#" id="decrypt"><img src="'+chrome.extension.getURL("images/decryptIcon.png")+'" width=13 height=13/ >Decrypt</a></span>');
                $(this).find('#decrypt').click(decrypt);
                $(this).append('<form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPasswordDecrypt"></form>');
                $(this).find('form[class="form-inline"]').submit(function(event){
                    $(this).parent().find('a[class="btn"]').click();
                    return false;
                });

                //TODO: <a class="btn" href="#" id="verifySignature">Check Signature</a>
                //$(this).find('#verifySignature').click(verifySignature);
                
                //TODO issues with inserting alert here. I think it has to do with subtreemodified not firing.
            }
        });
    }
    $('#canvas_frame').contents().find('#gCryptAlertPassword').hide();
    $('#canvas_frame').contents().find('#gCryptAlertEncryptNoUser').hide();
}

function onLoad() {
	if($('#canvas_frame').length == 1){
	   document.addEventListener("DOMSubtreeModified",function(){
	       composeIntercept();
	       //I've added the timeout because in threaded applications, proper DOM isn't loaded until after this event fires.
	       //TODO: I think there should be a better way to do this. Also note that DOM event handlers are being phased out..
           setTimeout(composeIntercept, 400);
           },false);
	   document.addEventListener("DOMFocusIn",function(){
	       composeIntercept();
           },false);
       }
    openpgp.init();
}

$(document).ready(onLoad);

