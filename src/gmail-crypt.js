/* This is the general class for gmail-crypt that runs within gmail context. 
 * 
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2. 
 * See included "LICENSE" file for details.
 */

var menubarLoaded = false;
var viewTitleBarLoaded = false;

function encrypt(){
	var form = $('#canvas_frame').contents().find('form');
    var to = gCryptUtil.parseUser(form.find('textarea[name="to"]').val()).userEmail;
	var contents = form.find('iframe[class="Am Al editable"]')[0].contentDocument.body;
   chrome.extension.sendRequest({method: "getPublicKey",email:to}, function(response){
        var publicKeyId = response.results[0].key_id;
        var publicKey = response.results[0].key;
        contents.innerText = OpenPGPEncode.encrypt(publicKeyId,0,publicKey,contents.innerText);
   });
}

function decrypt(event){
    var element = $(event.currentTarget).closest('[class="G3 G2"]').find('[class="ii gt"] div');
    //we need to use regex here because gmail will automatically form \n into <br> or <wbr>, strip these out
    var msg = element.html().replace(/(<br>)|(<wbr>)/g,'\n');
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
                    //Notify user no pgp text found
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
	var form = $('#canvas_frame').contents().find('form');
	var frame = form.find('iframe[class="Am Al editable"]');
	if (frame.length > 0){
    	var contents = frame[0].contentDocument.body;
	}
    var menubar = form.find('td[class="fA"]');
	if(menubar.length>0){
        if(menubar.find('#gCryptEncrypt').length == 0){
            menubar.append('<span id="gCryptEncrypt"><a href="#">encrypt me</a></span>');
            menubar[0].lastChild.addEventListener("click",encrypt,false);
        }
	}
	
	//Why is this not firing for all cases? It seems that if a page has been previously loaded it uses some sort of caching and won't fire the event
	var viewTitleBar = $('#canvas_frame').contents().find('div[class="G0"]');
    viewTitleBar.each(function(v){
        if( $(this).find('#gCryptDecrypt').length == 0){
	        $(this).prepend('<span id="gCryptDecrypt"><a href="#">decrypt me</a></span>');
            this.firstChild.addEventListener("click",decrypt,false);
        }
    });
}

function onLoad() {
	if($('#canvas_frame').length == 1){
	   document.addEventListener("DOMSubtreeModified",composeIntercept,false);
     }
    //SC I don't like the way this is run.
	OpenPGPEncode.rnTimer();
	eventsCollect();
}

$(document).ready(onLoad);

