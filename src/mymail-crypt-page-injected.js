const querystring = require('querystring');

// We need to override both `open` and the subsequent `send` XHR methods.
// We override `open` in order to get the URL we're sending to, to determine if the content is a draft.
// We override `send` because we get the content of the message. This will enable us to encrypt our drafts or handle things more intelligently.
function overrideDrafts() {
  const originalOpen = this.XMLHttpRequest.prototype.open;
  this.XMLHttpRequest.prototype.open = function () {
    const args = arguments; // eslint-disable-line prefer-rest-params
    if (args && args[1] && args[1].indexOf('autosave') > -1) {
      this._gCryptDraft = true; // eslint-disable-line no-underscore-dangle
    }
    return originalOpen.apply(this, [].slice.call(arguments)); // eslint-disable-line prefer-rest-params
  };

  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (data) {
    const params = querystring.parse(data);
    if (this._gCryptDraft && params.body) { // eslint-disable-line no-underscore-dangle
      this.abort();
    }
    return originalSend.call(this, data);
  };
}

overrideDrafts();
