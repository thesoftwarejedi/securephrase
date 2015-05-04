/**
 * Created by dana on 5/2/15.
 */

var bitcore = require('bitcore');
var Mnemonic = require('bitcore-mnemonic');

//have to explicitly set because secrets.js uses require === 'function' to detect node
//and bitcore defines require so they can be lazy and use it on the browser
var tempRequire = require;
require = null;
secrets.setRNG(); //set while require == null
require = tempRequire;


function validatePhrase() {
    var isValid = Mnemonic.isValid($('#txt1Secret').val());
    $('.phrase-valid').toggle(isValid);
    $('.phrase-invalid').toggle(!isValid);
}

function generateShares() {
    var phrase = $('#txt1Secret').val();
    var numShares = parseInt($('#txt1NumShares').val());
    var numRequired = parseInt($('#txt1NumRequired').val());

    var m = new Mnemonic(phrase);
    var keyHex = m.toHDPrivateKey().toObject().privateKey;

    var shares = secrets.share(keyHex, numShares, numRequired);
    var divShares = $('#div1Shares');
    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1);
        divShares.append('<span class="share-text">' + hexToBase64(shares[i]) + '</span><div class="share-qr-code" id="share' + i + '"></div>');
    }
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('share' + i), { text: hexToBase64(shares[i]), correctLevel: QRCode.CorrectLevel.H });
    }
}

function recoverShares() {
    var shares = $('#txt2Shares').val();
    var sharesArray = shares.split('\n');
    for (var i = 0; i < sharesArray.length; i++) {
        sharesArray[i] = '8' + base64ToHex(sharesArray[i]);
    }
    var hexSecret = secrets.combine(sharesArray);

    var key = bitcore.HDPrivateKey.fromSeed(hexSecret);
    $('#txt2Secret').val(key.xprivkey);
}

/**
 * helper functions, no outside entry
 */


function hexToBase64(str) {
    var tmp = chars_from_hex(str);
    return btoa(tmp);
}

function base64ToHex(str) {
    var tmp = atob(str);
    return hex_from_chars(tmp);
}

function chars_from_hex(inputstr) {
    var outputstr = '';
    inputstr = inputstr.replace(/^(0x)?/g, '');
    inputstr = inputstr.replace(/[^A-Fa-f0-9]/g, '');
    inputstr = inputstr.split('');
    for(var i=0; i<inputstr.length; i+=2) {
        outputstr += String.fromCharCode(parseInt(inputstr[i]+''+inputstr[i+1], 16));
    }
    return outputstr;
}

function hex_from_chars(inputstr) {
    var outputstr = '';
    var hex = "0123456789abcdef";
    hex = hex.split('');
    var i, n;
    var inputarr = inputstr.split('');
    for(var i=0; i<inputarr.length; i++) {
        n = inputstr.charCodeAt(i);
        outputstr += hex[(n >> 4) & 0xf] + hex[n & 0xf];
    }
    return outputstr;
}