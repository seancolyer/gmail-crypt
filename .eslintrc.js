module.exports = {
    env: {
      'es6': true,        // We are writing ES6 code
      'browser': true,    // for the browser
      'commonjs': true    // and use require() for stylesheets
    },
    "extends": "airbnb",
    "installedESLint": true,
    "plugins": [
        "react"
    ],
    sourceType: 'script',
    'rules': {
      'strict': [0, 'global'],
      'max-len': 0,
      'comma-dangle': [1, 'never'],
      'prefer-arrow-callback': 0,
      'import/no-extraneous-dependencies': 0,
      'import/no-unresolved': 0,
      'func-names': 0,
      'no-else-return': 0,
      'no-use-before-define': 0,
      'react/require-extension': 0,
      'brace-style': [1, 'stroustrup'],
      'no-undef': 1,
      'no-param-reassign': 1,
      'new-cap': [1, {'newIsCap': false}]
    }
};
