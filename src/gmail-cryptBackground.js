/* This is the background page for gmail-crypt that communicates between gmail and the extension.
 *
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */

//TODO how do we want to handle errors?
chrome.extension.onRequest.addListener(function(request,sender,sendResponse){
    openpgp.keyring.init(); //We need to handle changes that might have been made.
    if(request.method == "getAllPublicKeys"){
        sendResponse(openpgp.keyring.publicKeys);
    }
    if(request.method == "getPublicKeys"){
        var keys = {};
        for(var email in request.emails){
            try{
            if(request.emails[email].length>0){
                keys[request.emails[email]] = openpgp.keyring.getPublicKeyForAddress(request.emails[email])[0].armored;
                }
            }
            catch(e){

            }
        }
        if (request.myKeyId) {
            debugger;
            var myKey = openpgp.keyring.getPublicKeysForKeyId(request.myKeyId)[0];
            var myEmail = gCryptUtil.parseUser(myKey.obj.userIds[0].text).userEmail;
            keys[myEmail] = myKey.armored;
        }
        sendResponse(keys);
    }
    if(request.method == "getPublicKey"){
        sendResponse(openpgp.keyring.getPublicKeyForAddress(request.email));
    }
    if(request.method == "getPrivateKey"){
        sendResponse(openpgp.keyring.getPrivateKeyForAddress(request.email));
    }
    if(request.method == "getPrivateKeys"){
        sendResponse(openpgp.keyring.privateKeys);
    }
    if(request.method == "getOption"){
        openpgp.config.read();
        var gCryptSettings = openpgp.config.config.gCrypt;
        if(!gCryptSettings){
            sendResponse('');
        }
        else{
            sendResponse(gCryptSettings[request.option]);
        }
    }
    if(request.method == "getConfig"){
        sendResponse(openpgp.config);
    }
    else{
    }
});


function onLoad(){
    openpgp.init();
}

document.onload = onLoad();
