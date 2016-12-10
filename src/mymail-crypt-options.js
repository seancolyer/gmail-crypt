'use strict';

const angular = require('angular');
require('angular-aria');
require('angular-animate');
require('angular-material');
require('angular_material_css');
require('angular-validation-match');

const openpgp = require('openpgp');
// const gCryptUtil = require('./mymail-crypt-util.js');

const MODULE_NAME = 'mymailCrypt';

angular.module(MODULE_NAME, ['ngMaterial', 'ngAria', 'validation.match'])
  .controller('mainCtrl', ['$scope', '$rootScope', mainCtrl])
  .controller('privateKeyCtrl', ['$scope', '$rootScope', '$mdDialog', privateKeyCtrl])
  .controller('publicKeyCtrl', ['$scope', '$rootScope', '$mdDialog', publicKeyCtrl])
  .controller('optionsCtrl', ['$scope', '$rootScope', optionsCtrl])
  .config(['$mdIconProvider', function ($mdIconProvider) {
    $mdIconProvider
      .icon('copy', '../images/ic_content_copy_black_24px.svg')
      .icon('delete', '../images/ic_delete_black_24px.svg')
    ;
  }]);

function publicKeyCtrl($scope, $rootScope, $mdDialog) {
  $scope.keys = $rootScope.keyring.publicKeys.keys;
  this.errors = [];

  $scope.addNewKey = function () {
    const result = $rootScope.keyring.publicKeys.importKey(this.publicKeyArmored);
    if (result && result[0] && result[0].message) {
      this.errors = [result[0]];
    }
    $rootScope.keyring.store();
  };

  $scope.copyKey = function (event) {
    const range = document.createRange();

    range.selectNode(event.currentTarget.parentNode.parentNode.querySelector('.hidden-armored-key'));
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
    document.execCommand('copy');
  };

  $scope.showConfirmDelete = function (event) {
    const keyId = event.currentTarget.parentNode.parentNode.getAttribute('data-key-id');
    const confirm = $mdDialog.confirm()
          .title(`Would you like to remove the key ${keyId}?`)
          .content('You will NOT be able to recover it.')
          .parent(angular.element(document.body))
          .ok('Yes')
          .cancel('No');
    $mdDialog.show(confirm).then(function () {
      removeKey(keyId);
    });
  };

  // not using $scope assignment here because this should be called only from mdDialog promise confirmation
  const removeKey = function (keyId) {
    $rootScope.keyring.publicKeys.removeForId(keyId);
    $rootScope.keyring.store();
  };
}

function privateKeyCtrl($scope, $rootScope, $mdDialog) {
  $scope.keys = $rootScope.keyring.privateKeys.keys;
  $scope.generateKey = function () {
    const generateOptions = {
      numBits: parseInt(this.bits, 10),
      userIds: [{
        name: this.name,
        email: this.email
      }],
      passphrase: this.password
    };
    $rootScope.loading = true;
    const keyPair = openpgp.generateKey(generateOptions);
    keyPair.then(function (result) {
      $rootScope.keyring.privateKeys.importKey(result.privateKeyArmored);
      $rootScope.keyring.publicKeys.importKey(result.publicKeyArmored);
      $rootScope.keyring.store();
      $rootScope.loading = false;
      $scope.name = '';
      $scope.email = '';
      $scope.password = '';
      $scope.passwordConfirmation = '';
      $scope.generateKeyForm.$setUntouched();
      $scope.generateKeyForm.$setPristine();
      $rootScope.$apply();
    });
  };

  $scope.addNewKey = function () {
    const result = $rootScope.keyring.privateKeys.importKey(this.privateKeyArmored);
    if (result[0] && result[0].message) {
      this.errors = [result[0]];
    }
    $rootScope.keyring.store();
  };

  $scope.showConfirmDelete = function (event) {
    const keyId = event.currentTarget.parentNode.parentNode.getAttribute('data-key-id');
    const confirm = $mdDialog.confirm()
          .title(`Would you like to remove the key ${keyId}?`)
          .content('You will NOT be able to recover it.')
          .parent(angular.element(document.body))
          .ok('Yes')
          .cancel('No');
    $mdDialog.show(confirm).then(function () {
      removeKey(keyId);
    });
  };

  // not using $scope assignment here because this should be called only from mdDialog promise confirmation
  const removeKey = function (keyId) {
    $rootScope.keyring.privateKeys.removeForId(keyId);
    $rootScope.keyring.store();
  };
}

function optionsCtrl($scope, $rootScope) {
  const STOP_DRAFT_CONFIG_KEY = 'mymail-stopAutomaticDrafts';

  $scope.stopAutomaticDrafts = $rootScope.config.config[STOP_DRAFT_CONFIG_KEY];

  $scope.saveConfig = function () {
    $rootScope.config.config[STOP_DRAFT_CONFIG_KEY] = this.stopAutomaticDrafts;
    $rootScope.config.write();
  };
}

function mainCtrl($scope, $rootScope) {
  $rootScope.keyring = new openpgp.Keyring();
  $rootScope.config = new openpgp.config.localStorage();
  try {
    $rootScope.config.read();
  }
  catch (e) {
    console.error(e);
  }
  $rootScope.$on('refresh', function () {
    $scope.unread = mailManagement.getUnread();
  });
}
