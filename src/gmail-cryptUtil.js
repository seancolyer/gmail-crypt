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
    }

};
