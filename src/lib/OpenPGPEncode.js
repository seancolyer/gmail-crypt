
/* This is the decode component of the jsOpenPGP library. 
 * Derived from Herbert Hanewinkel's code.
 * Copyright 2011 Sean Colyer, <sean @ colyer . name>
 * Modifications licensed under the GNU General Public License Version 2. 
 * See "LICENSE" document included with this application for full information.
 * 
 * OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

/* We need an unpredictable session key of 128 bits ( = 2^128 possible keys).
 * If we generate the session key with a PRNG from a small seed we get only
 * a small number of session keys, e.g. 4 bytes seed => 2^32 keys, a brute
 * force attack could try all 2^32 session keys. 
 * (see RFC 1750 - Randomness Recommendations for Security.)
 *
 * Sources for randomness in Javascript are limited.
 * We have load, exec time, seed from random(), mouse movement events
 * and the timing from key press events.
 * But even here we have restrictions.
 * - A mailer will add a timestamp to the encrypted message, therefore
 *   only the msecs from the clock can be seen as unpredictable.
 * - Because the Windows timer is still based on the old DOS timer,
 *   the msecs jump under Windows in 18.2 msecs steps.
 * - Only a few bits from mouse mouvement event coordinates are unpredictable,
 *   if the same buttons are clicked on the screen.
 */
var OpenPGPEncode = {
    publicKeyMap : {'RSA' : 1},

    rnArray : new Array(256),
    rnNext : 0,
    rnRead : 0,

    randomByte: function() { return Math.round(Math.random()*255)&255; },
    timeByte: function() { return ((new Date().getTime())>>>2)&255; },

    rnTimer : function(){
     var t = this.timeByte(); // load time

     for(var i=0; i<256; i++)
     {
      t ^= this.randomByte();
      this.rnArray[(this.rnNext++)&255] ^= t;
     } 
     window.setTimeout("rnTimer()",this.randomByte()|128);
    },

    randomString: function(len, nozero)
    {
     var r = '';
     var t = this.timeByte(); // exec time

     for(var i=0; i<len;)
     {
       t ^= this.rnArray[(this.rnRead++)&255]^mouseByte()^keyByte();
       if(t==0 && nozero) continue;
       i++;

       r+=String.fromCharCode(t);
     }
     return r;
    },

    hex2s: function(hex){
     var r='';
     if(hex.length%2) hex+='0';

     for(var i = 0; i<hex.length; i += 2)
       r += String.fromCharCode(parseInt(hex.slice(i, i+2), 16));
     return r;
    },

    crc24: function(data){
     var crc = 0xb704ce;

     for(var n=0; n<data.length;n++)
     {
       crc ^=(data.charCodeAt(n)&255)<<16;
       for(i=0;i<8;i++)
       {
        crc<<=1;
        if(crc & 0x1000000) crc^=0x1864cfb;
       }       
     }
     return String.fromCharCode((crc>>16)&255)
            +String.fromCharCode((crc>>8)&255)
            +String.fromCharCode(crc&255);
    },

    // GPG CFB symmetric encryption using AES

    symAlg : 7,          // AES=7, AES192=8, AES256=9
    kSize  : [16,24,32],  // key length in bytes
    bpbl   : 16,         // bytes per data block

    GPGencrypt: function(key, text){
     var i, n;
     var len = text.length;
     var lsk = key.length;
     var iblock = new Array(this.bpbl)
     var rblock = new Array(this.bpbl);
     var ct = new Array(this.bpbl+2);
     var expandedKey = new Array();
     
     var ciphertext = '';

     // append zero padding
     if(len%this.bpbl)
     {
      for(i=(len%this.bpbl); i<this.bpbl; i++) text+='\0';
     }
     
     expandedKey = keyExpansion(key);

     // set up initialisation vector and random byte vector
     for(i=0; i<this.bpbl; i++)
     {
      iblock[i] = 0;
      rblock[i] = this.randomByte();
     }

     iblock = AESencrypt(iblock, expandedKey);
     for(i=0; i<this.bpbl; i++)
     {
      ct[i] = (iblock[i] ^= rblock[i]);
     }

     iblock = AESencrypt(iblock, expandedKey);
     // append check octets
     ct[this.bpbl]   = (iblock[0] ^ rblock[this.bpbl-2]);
     ct[this.bpbl+1] = (iblock[1] ^ rblock[this.bpbl-1]);
     
     for(i = 0; i < this.bpbl+2; i++) ciphertext += String.fromCharCode(ct[i]);

     // resync
     iblock = ct.slice(2, this.bpbl+2);

     for(n = 0; n < text.length; n+=this.bpbl)
     {
      iblock = AESencrypt(iblock, expandedKey);
      for(i = 0; i < this.bpbl; i++)
      {
       iblock[i] ^= text.charCodeAt(n+i);
       ciphertext += String.fromCharCode(iblock[i]);
      }
     }
     return ciphertext.substr(0,len+this.bpbl+2);
    },

    // GPG packet header (old format)

    GPGpkt: function(tag, len){
     if(len>255) tag +=1;
     var h = String.fromCharCode(tag);
     if(len>255) h+=String.fromCharCode(len/256);
     h += String.fromCharCode(len%256);
     return h;
    },

    // GPG public key encryted session key packet (1)

    //SC 10/25/11 I do not think el is used for anything...
    el : [3,5,9,17,513,2049,4097,8193],

    GPGpkesk : function(keyId, keytyp, symAlgo, sessionkey, pkey){ 
     var mod=new Array();
     var exp=new Array();
     var enc='';
     
     var s = r2s(pkey);
     var l = Math.floor((s.charCodeAt(0)*256 + s.charCodeAt(1)+7)/8);

     mod = new BigInteger(s.substr(0,l+2),'mpi');//mpi2b(s.substr(0,l+2));

     if(keytyp)
     {
      var grp= new BigInteger();
      var y  = new BigInteger();
      var B  = new BigInteger();
      var C  = new BigInteger();

      var l2 = Math.floor((s.charCodeAt(l+2)*256 + s.charCodeAt(l+3)+7)/8)+2;

      grp = new BigInteger(s.substr(l+2,l2),'mpi');//mpi2b(s.substr(l+2,l2));
      y   = new BigInteger(s.substr(l+2+l2),'mpi');//mpi2b(s.substr(l+2+l2));
      exp[0] = 9; //el[this.randomByte()&7];
      B = grp.modPow(exp,mod);//bmodexp(grp,exp,mod);
      C = y.modPow(exp,mod);//bmodexp(y,exp,mod);
     }
     else
     {
      exp = new BigInteger(s.substr(l+2),'mpi');//mpi2b(s.substr(l+2));
     }

     var lsk = sessionkey.length;

     // calculate checksum of session key
     var c = 0;
     for(var i = 0; i < lsk; i++) c += sessionkey.charCodeAt(i);
     c &= 0xffff;

     // create MPI from session key using PKCS-1 block type 02
     var lm = (l-2)*8+2;
     var m = String.fromCharCode(lm/256)+String.fromCharCode(lm%256)
       +String.fromCharCode(2)         // skip leading 0 for MPI
       +this.randomString(l-lsk-6,1)+'\0'   // add random padding (non-zero)
       +String.fromCharCode(symAlgo)+sessionkey
       +String.fromCharCode(c/256)+String.fromCharCode(c&255);

     if(keytyp)
     {
      // add Elgamal encrypted mpi values
      //SC 10/25/11 this needs to be verified
       enc = B.toMPI() + (new BigInteger(m,'mpi')).multiply(C).mod(mod).toMPI();//b2mpi(B)+b2mpi(bmod(bmul(mpi2b(m),C),mod));

      return this.GPGpkt(0x84,enc.length+10)
       +String.fromCharCode(3)+keyId+String.fromCharCode(16)+enc;
     }
     else
     {
      // rsa encrypt the result and convert into mpi
      enc = (new BigInteger(m,'mpi')).modPow(exp,mod).toMPI();//b2mpi(bmodexp(mpi2b(m),exp,mod));

      return this.GPGpkt(0x84,enc.length+10)
       +String.fromCharCode(3)+keyId+String.fromCharCode(1)+enc;
     }
    },

    // GPG literal data packet (11) for text file

    GPGld: function(text){
     if(text.indexOf('\r\n') == -1)
       text = text.replace(/\n/g,'\r\n');
     return this.GPGpkt(0xAC,text.length+10)+'t'
       +String.fromCharCode(4)+'file\0\0\0\0'+text;
    },

    // GPG symmetrically encrypted data packet (9)

    GPGsed: function(key, text){
     var enc = this.GPGencrypt(key, this.GPGld(text));
     return this.GPGpkt(0xA4,enc.length)+enc;
    },

    encrypt: function(keyId,keytyp,pkey,text){
     var keylen = this.kSize[this.symAlg-7];  // session key length in bytes

     var sesskey = this.randomString(keylen,0);
     keyId = this.hex2s(keyId);
     var cp = this.GPGpkesk(keyId,keytyp,this.symAlg,sesskey,pkey)+this.GPGsed(sesskey,text);

     return '-----BEGIN PGP MESSAGE-----\nVersion: jsOpenPGP v1\n\n'
            +s2r(cp)+'\n='+s2r(this.crc24(cp))+'\n-----END PGP MESSAGE-----\n';
    },
    
    //new style gpg header
    packet : function(tag, len){
    var header = 0xC0 + tag;
    header = String.fromCharCode(header);
    if(len<192){
        header += String.fromCharCode(len);
    }
    else if(len< 8383){
        var len1 = 191+Math.floor(len/256);
        var len2 = 256-(192-len%256);
        header += String.fromCharCode(len1)+String.fromCharCode(len2);
    }
    else if(len < 0xFFFFFFFF){
        header += String.fromCharCode(255) + String.fromCharCode(Math.floor(len/0x1000000%0x100)) + String.fromCharCode(Math.floor(len/0x10000%0x100)) + String.fromCharCode(Math.floor(len/0x100%0x100)) + String.fromCharCode(Math.floor(len%0x100));
    }
    // else length unknown, stream
    else{
    
    }
    return header;
    },
    
    buildTime: function(){
        var d = new Date();
        d = d.getTime()/1000
        return String.fromCharCode(Math.floor(d/0x1000000%0x100)) + String.fromCharCode(Math.floor(d/0x10000%0x100)) + String.fromCharCode(Math.floor(d/0x100%0x100)) + String.fromCharCode(Math.floor(d%0x100));
    },
    
    basicChecksum: function(text){
        var sum = 0;
        for(var n = 0; n < text; n++) sum += text.charCodeAt(n);
        return sum & 65535    
    },
    
    createSecretKeyPacket: function(){
        debugger;
        var packet = String.fromCharCode(4);
        packet += this.buildTime();
        packet += String.fromCharCode(this.publicKeyMap['RSA']);//public key algo
        var algorithmStart = packet.length;
        var rsa = new RSAKey();
        rsa.generate(2048,"10001");
        packet += rsa.n.toMPI();
        var e = new BigInteger();
        e.fromInt(rsa.e);
        packet += e.toMPI();
        packet += String.fromCharCode(0);//1 octet -- s2k, 0 for no s2k
        //optional: if s2k == 255,254 then 1 octet symmetric encryption algo
        //optional: if s2k == 255,254 then s2k specifier
        //optional if s2k, IV of same length as cipher's block
        packet += rsa.d.toMPI();
        packet += rsa.p.toMPI();
        packet += rsa.q.toMPI();
        packet += rsa.coeff.toMPI(); //is this actually u?
        packet += this.basicChecksum(packet.substr(algorithmStart));//DEPRECATED:s2k == 0, 255: 2 octet checksum, sum all octets%65536 
        packet = this.packet(5,packet.length) + packet;
        return '-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: jsOpenPGP v1\n\n'
            +s2r(packet)+'\n='+s2r(this.crc24(packet))+'\n-----END PGP MESSAGE-----\n';

    },
    
    createUserIdPacket: function(){
        var tag = 13;
        
    },
    
    createSignaturePacket: function(){
        var len = 100;
        var packet = this.packet(2,len);
        packet += String.fromCharCode(4);
        packet += String.fromCharCode(4); //version num
        packet += String.fromCharCode(0x10);//signature type
        packet += String.fromCharCode(this.publicKeyMap['RSA']);//public key algo
        packet += String.fromCharCode(2);//hash algo
        //2 octet count of hashed packets
        //hashed packets
        //2 octet count for non hashed packets
     
    }
}
