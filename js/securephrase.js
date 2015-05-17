/**
 * Created by dana on 5/2/15.
 */

//have to explicitly set because secrets.js uses require === 'function' to detect node
//and bitcore defines 'require' so they can be lazy and use it on the browser
var tempRequire = require;
require = null;
secrets.setRNG(); //set while require == null
require = tempRequire;

var r = new Random(Random.engines.browserCrypto);
var safePrintChars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"; //base 32, no 1 l 0 O

function generateShares() {
    var secret = $('#txt1Secret').val();
    var numShares = parseInt($('#txt1NumShares').val());
    var numRequired = parseInt($('#txt1NumRequired').val());
    var secretHex = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(secret));

    var shares = secrets.share(secretHex, numShares, numRequired);
    var divShares = $('#div1Shares');
    divShares.html('');

    //put in base64 with safeprint encryption or not
    var safePrintKey = '';
    if ($('#chkbxSafePrint').prop('checked')) {
        safePrintKey = r.string(10, safePrintChars); //base32 chars are good for writing keys down
        $('#safePrintKey').text(safePrintKey);
    }

    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1);

        //put in base64 with safeprint encryption or not
        if (safePrintKey != '') {
            //encrypt the share with the key
            var words = CryptoJS.enc.Hex.parse(shares[i]);
            var encryptedWords = CryptoJS.AES.encrypt(words, safePrintKey);
            shares[i] = encryptedWords.toString();
        } else {
            shares[i] = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Hex.parse(shares[i])); //put in base64 for display and qr
        }

        //we just build the qr code placeholder here, the next loop will actually generate the qr code
        divShares.append($('#tmplShare').render({text:shares[i], index:i+1}));
    }
    //generate the qr codes for the shares
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('shareQR' + (i+1)), { text: shares[i], correctLevel: QRCode.CorrectLevel.M, width: 512, height: 512 });
    }
}

function recoverShares() {
    var shares = $('#txt2Shares').val();
    var sharesArray = shares.split('\n');
    var safePrintKey = $('#txt2SafePrint').val();

    for (var i = 0; i < sharesArray.length; i++) {
        if (safePrintKey != '') {
            //there was a safeprint key so decrypt the share
            sharesArray[i] = CryptoJS.AES.decrypt(sharesArray[i], safePrintKey);
        } else {
            sharesArray[i] = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Base64.parse(sharesArray[i]));
        }
        //pop the stupid 8 back on
        sharesArray[i] = '8' + sharesArray[i];
    }
    var hexSecret = secrets.combine(sharesArray);
    var secret = CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Hex.parse(hexSecret));
    $('#txt2Secret').val(secret);
}
