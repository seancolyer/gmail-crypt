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
	var form = $('#canvas_frame').contents().find('form');
    var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
	var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
	var privKey;
	//TODO: make using a signature optional.
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        privKey = openpgp.read_privateKey(response[0].armored)[0];
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

function decrypt(event){
    var element;
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
    msg = msg[0];
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        for(var r = 0; r<response.length;r++){
            debugger;
            var key = openpgp.read_privateKey(response[r].armored)[0];
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
            menubar.append('<span id="gCryptEncrypt"><a href="#"><img src="'+chrome.extension.getURL("images/encryptIcon.png")+'"/>encrypt me</a></span>');
            menubar[0].lastChild.addEventListener("click",encrypt,false);
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
	            $(this).prepend('<span id="gCryptDecrypt"><a href="#"><img src="'+chrome.extension.getURL("images/decryptIcon.png")+'"/>decrypt me</a></span>');
                $(this).find('#gCryptDecrypt').click(decrypt);
            }
        });
    }
}

function onLoad() {
	if($('#canvas_frame').length == 1){
	   document.addEventListener("DOMSubtreeModified",composeIntercept,false);
     }
    openpgp.init();
}

$(document).ready(onLoad);

