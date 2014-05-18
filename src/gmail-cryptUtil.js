/* This is a collection of utilities for gmail-crypt.
 *
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */


var gCryptUtil = {
    noArmoredText: 'No encrypted message detected',

    parseUser: function(user){
       try{
           var userName = user.substring(0,user.indexOf('<')-1);
           var userEmail = user.substring(user.indexOf('<')+1,user.indexOf('>'));
           if(user.indexOf('<') === -1){ //no < found, assume just an email address
            if(user.indexOf('@') === -1){
                throw "No Email Address";}
            userName = '';
            userEmail = user.substring(0, user.indexOf(' '));
            if(userEmail.substring(0,userEmail.indexOf(',')) != -1){
                userEmail = user.substring(0, user.indexOf(','));
                }
            if(userEmail.length === 0){
                userEmail = user;
            }
           }
           return {userName: userName, userEmail: userEmail};
       }
       catch(e){
           this.notify('No User Found');
           return {userName: '', userEmail: ''};
       }
    },

    notify: function(msg){
    },

    getOption: function (config, optionName, thirdParty) {
      if(!config.config) {
        throw new Error("config is not properly set up");
      }
      if (thirdParty) {
        var gCryptSettings = config.config.thirdParty;
        if(!gCryptSettings || !gCryptSettings.mymailCrypt){
          return;
        }
        else{
          return gCryptSettings.mymailCrypt[optionName];
        }
      }
      else {
        return config.config[optionName];
      }
    },

    setOption: function(config, optionName, value, thirdParty) {
      if (!config.config) {
        throw new Error("config is not properly set up");
      }
      if (!config.config.thirdParty) {
          config.config.thirdParty = {
            mymailCrypt: {}
          };
      }
      if (thirdParty) {
        var gCryptSettings = config.config.thirdParty.mymailCrypt;
        gCryptSettings[optionName] = value;
      }
      else {
        config.config[optionName] = value;
      }
      config.write();
    }

};
