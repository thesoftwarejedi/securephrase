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
    var secretHex = asc2hex(secret);

    var shares = secrets.share(secretHex, numShares, numRequired);
    var divShares = $('#div1Shares');
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
            shares[i] = hex2b64(shares[i]); //put in base64 for display and qr
        }

        //we just build the qr code placeholder here, the next loop will actually generate the qr code
        divShares.append('<span class="share-text">' + shares[i] + '</span><div class="share-qr-code" id="share' + i + '" /><div class="share-safe-print">' + safePrintKey + '</div>');
    }
    //generate the qr codes for the shares
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('share' + i), { text: shares[i], correctLevel: QRCode.CorrectLevel.M });
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
            sharesArray[i] = b642hex(sharesArray[i]);
        }
        //pop the stupid 8 back on
        sharesArray[i] = '8' + sharesArray[i];
    }
    var hexSecret = secrets.combine(sharesArray);
    var secret = hex2asc(hexSecret);
    $('#txt2Secret').val(secret);
}
