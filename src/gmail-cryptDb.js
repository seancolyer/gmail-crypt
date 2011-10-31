
/* This is the HTML5 WebDatabase class used for gmail-crypt. 
 * 
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2. 
 * See included "LICENSE" file for details.
 */

var gCryptDb = {
    connection : '',
    setupDb: function(){
        connection =  openDatabase('gmail-crypt','1.0','gmail-crypt-keystore',5*1024*1024);
        connection.transaction(function (t){
        t.executeSql('CREATE TABLE IF NOT EXISTS publicKey (id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR, email VARCHAR, key VARCHAR, key_version VARCHAR, key_fp VARCHAR, key_id VARCHAR, key_raw VARCHAR)');
        t.executeSql('CREATE TABLE IF NOT EXISTS privateKey (id INTEGER PRIMARY KEY AUTOINCREMENT, name, email, key, key_id, d, p, q, u)');
        }); 
      },
      
    dropDb: function(){
        connection.transaction(function (t){
            t.executeSql('drop table publicKey');
            t.executeSql('drop table privateKey');    
        });
    },

    query: function(query,inputs,callbackSuccess,callbackError){
      connection.transaction(function (t){
         t.executeSql(query,inputs, function (t, results){
            var rows = [];
            for(var r = 0; r < results.rows.length ; r++){
               rows.push(results.rows.item(r));
               }
            callbackSuccess(rows);
            }, callbackError);
         });
    },
      
    queryPublicKeys: function(successFunction, errorFunction){
       this.query('SELECT * FROM publicKey',[], successFunction, errorFunction);
    },
   
    queryPrivateKeys: function(successFunction, errorFunction){
       this.query('SELECT * FROM privateKey',[], successFunction, errorFunction);
    },

    insertPrivateKey: function(user, key, key_id, d, p, q, u, successFunction, errorFunction){
        var userInfo = gCryptUtil.parseUser(user);
        var insertQuery = "INSERT INTO privateKey (name, email, key, key_id, d, p, q, u) values ('"+userInfo.userName+"','"+userInfo.userEmail+"','"+key+"','"+key_id+"','"+d+"','"+p+"','"+q+"','"+u+"')";
        this.query(insertQuery,[],successFunction,errorFunction);
    },

    insertPublicKey: function(vers, fp, keyId, user, key, keyRaw, successFunction, errorFunction){
        var userInfo = gCryptUtil.parseUser(user);
        var insertQuery = "INSERT INTO publicKey (name, email, key, key_version, key_fp, key_id, key_raw) values ('"+userInfo.userName+"','"+userInfo.userEmail+"','"+key+"','"+vers+"','"+fp+"','"+keyId+"','"+keyRaw+"')";
        this.query(insertQuery,[],successFunction,errorFunction);
    },
   
    removePublicKey: function(keyId, successFunction, errorFunction){
        var queryString = "DELETE FROM publicKey WHERE id = '"+keyId+"'";
        this.query(queryString,[], successFunction, errorFunction);
    },
    removePrivateKey: function(keyId, successFunction, errorFunction){
        var queryString = "DELETE FROM privateKey WHERE id = '"+keyId+"'";
        this.query(queryString,[], successFunction, errorFunction);
    }

}
