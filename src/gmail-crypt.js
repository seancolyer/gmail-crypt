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

function encrypt(){
	var form = $('#canvas_frame').contents().find('form');
    var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
	var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
   chrome.extension.sendRequest({method: "getPublicKey",email:to}, function(response){
        debugger;
        if(response.length == 0){
                gCryptUtil.notify('No keys found for this user.');
                return;
        }
        contents.innerText = openpgp.write_encrypted_message(response[0],contents.innerText);
        //var publicKeyId = response.results[0].key_id;
        //var publicKey = response.results[0].key;
        //contents.innerText = OpenPGPEncode.encrypt(publicKeyId,0,publicKey,contents.innerText);
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
    chrome.extension.sendRequest({method: "getPrivateKeys"}, function(response){
        for(var r = 0; r<response.results.length;r++){
            var key = response.results[r];
            var rsa = new RSAKey();
            rsa.setPrivateAutoComplete(new BigInteger(key.p, 16),new BigInteger(key.q, 16),new BigInteger(key.d, 16));
            try{
                var results = OpenPGPDecode.decode(msg, rsa);
                var text = '';
                for(var n=0; n<results.length;n++){
                    if(results[n].tag==11){
                        text = results[n].text
                    }
                }
                if(text.length > 0){
                    element.html(text.replace(/\n/g,'<br>'));
                    return;
                }
                else{
                    gCryptUtil.notify('No text found');
                }
            }
            catch(e){
                if(e == gCryptUtil.noArmoredText){
                    gCryptUtil.notify(e);
                    return;
                }
            }
        }
        gCryptUtil.notify('Unable to decrypt this message.');
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
                //this.firstChild.addEventListener("click",decrypt,false);
            }
        });
    }
}

function onLoad() {
	if($('#canvas_frame').length == 1){
	   document.addEventListener("DOMSubtreeModified",composeIntercept,false);
     }
    openpgp.init();
    //SC I don't like the way this is run.
	//OpenPGPEncode.rnTimer();
	//eventsCollect();
}

$(document).ready(onLoad);

