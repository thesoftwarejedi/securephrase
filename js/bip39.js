/**
 * Created by dana on 5/2/15.
 *
 * DO NOT MAINTAIN THIS, I DON'T THINK I'M GOING TO USE IT.  IT ONLY BACKS UP THE XPRV, NOT THE PHRASE
 *
 */

var bitcore = require('bitcore');
var Mnemonic = require('bitcore-mnemonic');

//have to explicitly set because secrets.js uses require === 'function' to detect node
//and bitcore defines require so they can be lazy and use it on the browser
var tempRequire = require;
require = null;
secrets.setRNG(); //set while require == null
require = tempRequire;

var r = new Random(Random.engines.browserCrypto);
var safePrintChars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"; //base 32, no 1 l 0 O

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
    divShares.html('');
    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1);

        //put in base64 with safeprint encryption or not
        var safePrintKey = '';
        if ($('#chkbxSafePrint').prop('checked')) {
            safePrintKey = r.string(6, safePrintChars); //base58 chars are good for writing keys down
            //encrypt the share with the key
            var words = CryptoJS.enc.Hex.parse(shares[i]);
            var encryptedWords = CryptoJS.AES.encrypt(words, safePrintKey);
            shares[i] = encryptedWords.toString();
        } else {
            shares[i] = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Hex.parse(shares[i])); //put in base64 for display and qr
        }
        divShares.append($('#tmplShare').render({text:shares[i], index:i, safePrintKey:safePrintKey }));
    }
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('shareQR' + i), { text: shares[i], correctLevel: QRCode.CorrectLevel.H });
    }
}

function recoverShares() {
    var shares = $('#txt2Shares').val();
    var sharesArray = shares.split('\n');
    for (var i = 0; i < sharesArray.length; i++) {
        var safePrintCheck = sharesArray[i].split(';');
        if (safePrintCheck.length > 1) {
            //there was a safeprint key so decrypt the share
            sharesArray[i] = CryptoJS.AES.decrypt(safePrintCheck[0], safePrintCheck[1]);
        } else {
            sharesArray[i] = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Base64.parse(sharesArray[i]));
        }
        //pop the stupid 8 back on
        sharesArray[i] = '8' + sharesArray[i];
    }
    var hexSecret = secrets.combine(sharesArray);

    var key = bitcore.HDPrivateKey.fromSeed(hexSecret);
    $('#txt2Secret').val(key.xprivkey);
}
