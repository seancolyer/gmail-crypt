/*
 * This is a collection of utilities for mymail-crypt for Gmail.
 *
 * Copyright 2011-2014 Sean Colyer, <sean @ colyer . name>
 * This program is licensed under the GNU General Public License Version 2.
 * See included "LICENSE" file for details.
 */
const _ = require('lodash');

function parseUser(user) {
  try {
    let userName = user.substring(0, user.indexOf('<') - 1);
    let userEmail = user.substring(user.indexOf('<') + 1, user.indexOf('>'));
    if (user.indexOf('<') === -1) { // no < found, assume just an email address
      if (user.indexOf('@') === -1) {
        throw new Error('No Email Address');
      }
      userName = '';
      userEmail = user.substring(0, user.indexOf(' '));
      if (userEmail.substring(0, userEmail.indexOf(',')) !== -1) {
        userEmail = user.substring(0, user.indexOf(','));
      }
      if (userEmail.length === 0) {
        userEmail = user;
      }
    }
    return {
      userName,
      userEmail,
      error: null
    };
  }
  catch (e) {
    return {
      userName: '',
      userEmail: '',
      error: 'No User Found'
    };
  }
}

function getOption(config, optionName, thirdParty) {
  if (!config.config) {
    throw new Error('config is not properly set up');
  }
  if (thirdParty) {
    const gCryptSettings = config.config.thirdParty;
    if (!gCryptSettings || !gCryptSettings.mymailCrypt) {
      return {};
    }
    else {
      return gCryptSettings.mymailCrypt[optionName];
    }
  }
  else {
    return config.config[optionName];
  }
}

function setOption(config, optionName, value, thirdParty) {
  if (!config.config) {
    throw new Error('config is not properly set up');
  }
  if (!config.config.thirdParty) {
    config.config.thirdParty = {
      mymailCrypt: {}
    };
  }
  if (thirdParty) {
    const gCryptSettings = config.config.thirdParty.mymailCrypt;
    gCryptSettings[optionName] = value;
  }
  else {
    config.config[optionName] = value;
  }
  config.write();
}

function migrateOldKeys(keyring) {
  let keys;
  // Note that below we are not removing the old keys, for backwards compatibility, might remove evenutally.
  if (localStorage) {
    if (localStorage.publickeys) {
      keys = JSON.parse(localStorage.publickeys);
      _.each(keys, function (key) {
        keyring.publicKeys.importKey(key);
      });
      localStorage.publickeysBackup = localStorage.publickeys;
      localStorage.removeItem('publickeys');
    }
    if (localStorage.privatekeys) {
      keys = JSON.parse(localStorage.privatekeys);
      _.each(keys, function (key) {
        keyring.privateKeys.importKey(key);
      });
      localStorage.privatekeysBackup = localStorage.privatekeys;
      localStorage.removeItem('privatekeys');
    }
  }
  keyring.store();
}

module.exports = {
  getOption,
  setOption,
  migrateOldKeys,
  parseUser
};
