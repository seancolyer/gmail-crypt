   var privateKeyFormToggle = true;
   var publicKeyFormToggle = true;
   var generateKeyFormToggle = true;
   
   function generateKeyPair(){
        $('.alert').hide();
        var form = $('#generateKeyPairForm');
        var keyPair = openpgp.generate_key_pair(1,parseInt(form.find('#numBits').val(), 10), form.find('#name').val() + ' <' + form.find('#email').val() + '>', form.find('#password').val());
        openpgp.keyring.importPrivateKey(keyPair.privateKeyArmored, form.find('#password').val());
        openpgp.keyring.importPublicKey(keyPair.publicKeyArmored);
        openpgp.keyring.store();
        parsePrivateKeys();
        parsePublicKeys();
   }
   
   function insertPrivateKey(){
        $('.alert').hide();
       var privKey = $('#newPrivateKey').val();
       var privKeyPassword = $('#newPrivateKeyPassword').val();
       try{
           if(openpgp.keyring.importPrivateKey(privKey, privKeyPassword)){
            openpgp.keyring.store();
            parsePrivateKeys();
            return true;
           }
           else{
            $('#insertPrivateKeyForm').prepend('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt for Gmail was unable to read your key. Is your password correct?</div>');
           }
       }
       catch(e){
       }
        $('#insertPrivateKeyForm').prepend('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt for Gmail was unable to read your key. It would be great if you could contact us so we can help figure out what went wrong.</div>');
        return false;
   }
    
   function insertPublicKey(){
        $('.alert').hide();
        var pubKey = $('#newPublicKey').val();
        try{
            openpgp.keyring.importPublicKey(pubKey);
            openpgp.keyring.store();
            parsePublicKeys();
            return true;
        }
        catch(e){
        }
        $('#insertPublicKeyForm').prepend('<div class="alert alert-error" id="gCryptAlertPassword">Mymail-Crypt for Gmail was unable to read this key. It would be great if you could contact us so we can help figure out what went wrong.</div>');
        return false;
   }
   
   function parsePublicKeys(){
      var keys = openpgp.keyring.publicKeys;
      $('#publicKeyTable>tbody>tr').remove();
      for(var k=0;k<keys.length;k++){
          var key = keys[k];
          var user = gCryptUtil.parseUser(key.obj.userIds[0].text);
          $('#publicKeyTable>tbody').append('<tr><td class="removeLink" id="'+k+'"><a href="#">remove</a></td><td>'+user.userName+'</td><td>'+user.userEmail+'</td><td>'+util.hexstrdump(key.keyId)+'</td><td><a href="#public'+k+'" data-toggle="modal">show key</a>'+
		  '<div class="modal" id="public'+k+'"><div class="modal-dialog"><div class="modal-content">' +
		  '<div class="modal-body"><pre>'+key.armored + '</pre></div>' +
		  '<div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Close</button></div>' +
		  '</div></div></div></td></tr>');
          $('#public'+k).hide();
          $('#public'+k).modal({backdrop: true, show: false});
      }
      $('#publicKeyTable .removeLink').click(function(e){
        openpgp.keyring.removePublicKey(e.currentTarget.id);
        openpgp.keyring.store();
        parsePublicKeys();
        });
   }
   
   function parsePrivateKeys(){
      var keys = openpgp.keyring.privateKeys;
      $('#privateKeyTable>tbody>tr').remove();
      for(var k=0;k<keys.length;k++){
          var key = keys[k];
          var user = gCryptUtil.parseUser(key.obj.userIds[0].text);
          $('#privateKeyTable>tbody').append('<tr><td class="removeLink" id="'+k+'"><a href="#">remove</a></td><td>'+user.userName+'</td><td>'+user.userEmail+'</td><td><a href="#private'+k+'" data-toggle="modal">show key</a>' +
		  '<div class="modal" id="private'+k+'"><div class="modal-dialog"><div class="modal-content">' +
		  '<div class="modal-body"><pre>'+key.armored + '</pre></div>' +
		  '<div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Close</button></div>' +
		  '</div></div></div></td></tr>');
          $('#private'+k).hide();
          $('#private'+k).modal({backdrop: true, show: false});
      }
      $('#privateKeyTable .removeLink').click(function(e){
        openpgp.keyring.removePrivateKey(e.currentTarget.id);
        openpgp.keyring.store();
        parsePrivateKeys();
      });
   }

    /**
     * We use openpgp.config for storing our options.
     */
   function saveOptions(){
        var gCryptSettings = openpgp.config.config.gCrypt;
        if(!gCryptSettings){
            gCryptSettings = {};
        }
        if($('#stopAutomaticDrafts:checked').length == 1){
            gCryptSettings.stopAutomaticDrafts = true;
        } else {
            gCryptSettings.stopAutomaticDrafts = false;
        }
        if($('#includeMyself:checked').length == 1){
            gCryptSettings.includeMyself = true;
        } else {
            gCryptSettings.includeMyself = false;
        }
        if($('#showComment:checked').length == 1){
            openpgp.config.config.show_comment = true;
        } else {
            openpgp.config.config.show_comment = false;
        }
        if($('#showVersion:checked').length == 1){
            openpgp.config.config.show_version = true;
        } else {
            openpgp.config.config.show_version = false;
        }
		
		var $pwdto = $('#passwordTimeout');
		if ($pwdto.val() >= 0 && $pwdto.val() <= 30) {
			openpgp.config.config.password_timeout = $pwdto.val();
		} else {
			openpgp.config.config.password_timeout = 5;
		}
        
        openpgp.config.config.gCrypt = gCryptSettings;
        openpgp.config.write();
   }
   
   function loadOptions(){
        var gCryptSettings = openpgp.config.config.gCrypt;
        if (gCryptSettings && gCryptSettings.stopAutomaticDrafts){
            $('#stopAutomaticDrafts').attr('checked', true);
        }
        if (gCryptSettings && gCryptSettings.includeMyself) {
            $('#includeMyself').attr('checked', true);
        }
        if (openpgp.config.config.show_comment){
            $('#showComment').attr('checked', true);
        }
        if (openpgp.config.config.show_version){
            $('#showVersion').attr('checked', true);
        }
		if (openpgp.config.config.password_timeout) {
			$('#passwordTimeout').val(openpgp.config.config.password_timeout);
		} else {
			$('#passwordTimeout').val(5);
		}
   }

   function linkLocalFunction(event){
       $('.alert').hide();
       $('span').hide();
       if(event && event.currentTarget){
        $(event.currentTarget.hash).show();
       }
   }
   
    function onLoad(){
        openpgp.init();
        parsePrivateKeys();
        parsePublicKeys();
        loadOptions();
        $('.linkLocal').click(linkLocalFunction).click();
        $('#homeSpan').show();
        $('#generateKeyPairForm').hide();
        $('#generateKeyPairTitle').click(function() {
            $('#generateKeyPairForm').toggle(generateKeyFormToggle);
            generateKeyFormToggle = !generateKeyFormToggle;
        });      
        $('#insertPrivateKeyForm').hide();
        $('#insertPrivateKeyTitle').click(function() {
            $('#insertPrivateKeyForm').toggle(privateKeyFormToggle);
            privateKeyFormToggle = !privateKeyFormToggle;
        });
        $('#insertPublicKeyForm').hide();
        $('#insertPublicKeyTitle').click(function() {
            $('#insertPublicKeyForm').toggle(publicKeyFormToggle);
            publicKeyFormToggle = !publicKeyFormToggle;
        });
        $('#optionsFormSubmit').click(saveOptions);
        $('#insertPrivateKeyFormSubmit').click(insertPrivateKey);
        $('#generateKeyPairFormSubmit').click(generateKeyPair);
        $('#insertPublicKeyFormSubmit').click(insertPublicKey);
      }

   $(document).ready(onLoad());
