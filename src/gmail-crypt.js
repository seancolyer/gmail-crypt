/* This is the general class for gmail-crypt that runs within gmail context. 
 * 
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
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

function encrypt(){
    debugger;
    var form = $('#canvas_frame').contents().find('form');
    form.find('.alert-error').hide();
    var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
    var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
    chrome.extension.sendRequest({method: "getPublicKey",email:to}, function(response){
        debugger;
        var pubKey = openpgp.read_publicKey(response[0].armored);
        if(response.length == 0){
                gCryptUtil.notify('No keys found for this user.');
                return;
        }
        contents.innerText = openpgp.write_encrypted_message(pubKey,contents.innerText);
        });
}

function encryptAndSign(){
    var form = $('#canvas_frame').contents().find('form');
    form.find('.alert-error').hide();
    var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
	var privKey;
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        privKey = openpgp.read_privateKey(response[0].armored)[0];
        if(!privKey.decryptSecretMPIs()){
            var password = $('#canvas_frame').contents().find('#gCryptPassword').val();
            if(!privKey.decryptSecretMPIs(password))
                form.find('#gCryptAlertPassword').show();
        }
        var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
        chrome.extension.sendRequest({method: "getPublicKey",email:to}, function(response){
            debugger;
            var pubKey = openpgp.read_publicKey(response[0].armored);
            if(response.length == 0){
                    gCryptUtil.notify('No keys found for this user.');
                    return;
            }
            contents.innerText = openpgp.write_signed_and_encrypted_message(privKey,pubKey,contents.innerText);
            });

        });
}

function sign(){
    var form = $('#canvas_frame').contents().find('form');
    form.find('.alert-error').hide();
    var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
	var privKey;
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        debugger;
        privKey = openpgp.read_privateKey(response[0].armored)[0];
        if(!privKey.decryptSecretMPIs()){
            var password = $('#canvas_frame').contents().find('#gCryptPassword').val();
            if(!privKey.decryptSecretMPIs(password))
                form.find('#gCryptAlertPassword').show();
        }
        contents.innerText = openpgp.write_signed_message(privKey,contents.innerText);
        });

}

function getMessage(){
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
        gCryptUtil.notify('No message found');
        return;
    }
    return [element, msg[0]];

}

function decrypt(event){
    $('#canvas_frame').contents().find('.alert-error').hide();
    var setup = getMessage();
    var element = setup[0];
    var msg = setup[1];
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        for(var r = 0; r<response.length;r++){
            debugger;
            var key = openpgp.read_privateKey(response[r].armored)[0];
            if(!key.decryptSecretMPIs()){
                var password = $('#canvas_frame').contents().find('#gCryptPassword').val();
                if(!key.decryptSecretMPIs(password))
               	    $('#canvas_frame').contents().find('div[class="gE iv gt"]').append('<div class="alert alert-error" id="gCryptAlertPassword">gmail-crypt was unable to read your key. Is your password correct?</div>');
            }
            var material = {key: key , keymaterial: key.privateKeyPacket};
            var sessionKey = msg.sessionKeys[0];
            var text = msg.decrypt(material, sessionKey);
            if(text != ''){
                element.html(text.replace(/\n/g,'<br>'));
                return;
                }
			for (var j = 0; j < key.subKeys.length; j++) {
				keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
				sesskey = msg[0].sessionKeys[i];
                text = msg.decrypt(material, sessionKey);
                if(text != ''){
                    element.html(text.replace(/\n/g,'<br>'));
                    return;
                    }
    		    }
            }
        gCryptUtil.notify('I can\'t decrypt this.');
        });
    }

//TODO: this has not yet been completed in openpgp.js
function verifySignature(){
    var setup = getMessage();
    var msg = setup[1];
    debugger;
    var form = $('#canvas_frame').contents().find('form');
    var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
    var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
    //TODO: this should be updated to only query for certain public keys
    chrome.extension.sendRequest({method: "getPublicKeys"}, function(response){
        debugger;
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
            menubar.append('<span id="gCryptEncrypt" class="btn-group"><a class="btn" href="#" id="encryptAndSign1"><img src="'+chrome.extension.getURL("images/encryptIcon.png")+'" width=13 height=13/> Encrypt</a><a class="btn dropdown-toggle" data-toggle="dropdown" href="#"><span class="caret"></span></a><ul class="dropdown-menu"><li id="encryptAndSign2"><a href="#">Encrypt (sign)</a></li><li id="encrypt"><a href="#">Encrypt (don\'t sign)</a></li><li id="sign"><a href="#">Sign only</a></li></ul></span><form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPassword"></form>');
            menubar.find('#encryptAndSign1').click(encryptAndSign);
            menubar.find('#encryptAndSign2').click(encryptAndSign);
            menubar.find('#encrypt').click(encrypt);
            menubar.find('#sign').click(sign);
            form.find('.eJ').append('<div class="alert alert-error" id="gCryptAlertPassword">gmail-crypt was unable to read your key. Is your password correct?</div>');
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
                $(this).append('<form class="form-inline"><input type="password" class="input-small" placeholder="password" id="gCryptPassword"></form>');
                //TODO: <a class="btn" href="#" id="verifySignature">Check Signature</a>
                //$(this).find('#verifySignature').click(verifySignature);
                
                //TODO issues with inserting alert here. I think it has to do with subtreemodified not firing.
            }
        });
    }
    $('#canvas_frame').contents().find('#gCryptAlertPassword').hide();
}

function onLoad() {
	if($('#canvas_frame').length == 1){
	   document.addEventListener("DOMSubtreeModified",composeIntercept,false);
     }
    openpgp.init();
}

$(document).ready(onLoad);

