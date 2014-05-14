# What is this?
**Mymail-Crypt for Gmail** is a browser (Chrome) extension that brings OpenPGP support to gmail. It aims to be a simple solution to mail encryption.

## Download and usage

It is available in the [chrome web store](https://chrome.google.com/webstore/detail/mymail-crypt-for-gmail/jcaobjhdnlpmopmjhijplpjhlplfkhba). This page also links to [youtube](https://www.youtube.com/watch?feature=player_embedded&v=aAXIqnjbc-M) which gives a quick overview on how to use the extension.

It is important to familiarize yourself with **Options** page, where keys will be loaded and other options set.

# How does it work?

The project is built on top of JavaScript OpenPGP library [OpenPGP.js](https://github.com/openpgpjs/openpgpjs). The extension uses the Chromium concept of *Content Scripts* to interact with the Gmail interface. It uses jQuery to manipulate the Gmail page.

# More information
I sometimes post about this project at [prometheusx.net](http://prometheusx.net).

# Contribution

Additional help welcome. If the changes you're interested in making are in the OpenPGP component, please take a look at [OpenPGP.js](https://github.com/openpgpjs/openpgpjs).

# Licensing
See LICENSE file for licensing info.
