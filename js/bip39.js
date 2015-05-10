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
    $('#txt1SecretHex').val(keyHex);

    var shares = secrets.share(keyHex, numShares, numRequired);
    var divShares = $('#div1Shares');
    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1);
        divShares.append('<span class="share-text">' + hex2b64(shares[i]) + '</span><div class="share-qr-code" id="share' + i + '"></div>');
    }
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('share' + i), { text: hex2b64(shares[i]), correctLevel: QRCode.CorrectLevel.H });
    }
}

function recoverShares() {
    var shares = $('#txt2Shares').val();
    var sharesArray = shares.split('\n');
    for (var i = 0; i < sharesArray.length; i++) {
        sharesArray[i] = '8' + b642hex(sharesArray[i]);
    }
    var hexSecret = secrets.combine(sharesArray);

    var key = bitcore.HDPrivateKey.fromSeed(hexSecret);
    $('#txt2Secret').val(key.xprivkey);
}
