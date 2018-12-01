/**
 * Created by dana on 5/2/15.
 *
 * Compatibility version 1
 * 
 * Backward compatibility breaking changes 
 * should increment this version number
 */

//have to explicitly set because secrets.js uses require === 'function' to detect node
//and bitcore defines 'require' so they can be lazy and use it on the browser
var tempRequire = require;
require = null;
secrets.setRNG(); //set while require == null
require = tempRequire;

var r = new Random(Random.engines.browserCrypto);
var safePrintChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; //base 57, no 1 I l 0 O

function generateShares() {
    var secret = $('#txt1Secret').val();
    var numShares = parseInt($('#txt1NumShares').val());
    var numRequired = parseInt($('#txt1NumRequired').val());
    var secretHex = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(secret));

    var shares = secrets.share(secretHex, numShares, numRequired);
    var divShares = $('#div1Shares');
    divShares.html('');

    //get safe key
    var safePrintKey = '';
    var isSafeKey = $('#chkbxSafePrint').prop('checked');

    if (isSafeKey) {
        $('.safe-key-wrap').show();
        safePrintKey = r.string(10, safePrintChars); //chars which are good for writing keys down
        $('#safePrintKey').text(safePrintKey);
    } else {
        $('.safe-key-wrap').hide();
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
        divShares.append($('#tmplShare').render({
            text: shares[i],
            index: i + 1
        }));
    }
    //generate the qr codes for the shares
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('shareQR' + (i + 1)), {
            text: shares[i],
            correctLevel: QRCode.CorrectLevel.L,
            width: 256,
            height: 256
        });
    }
}

function recoverShares() {
    try {
        var shares = $('#txt2Shares').val();
        var sharesArray = shares.split('\n');
        var safePrintKey = $('#txt2SafePrint').val();

        var sharesArrayHex = [];
        for (var i = 0; i < sharesArray.length; i++) {
            if (sharesArray[i].trim().length == 0) continue;
            if (safePrintKey != '') {
                //there was a safeprint key so decrypt the share
                sharesArray[i] = CryptoJS.AES.decrypt(sharesArray[i], safePrintKey);
            } else {
                $('.safe-key-wrap').toggle(false);
                sharesArray[i] = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Base64.parse(sharesArray[i]));
            }
            //pop the stupid 8 back on
            sharesArray[i] = '8' + sharesArray[i];
            sharesArrayHex.push(sharesArray[i]);
        }
        var hexSecret = secrets.combine(sharesArrayHex);
        var secret = CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Hex.parse(hexSecret));
        $('#txt2Secret').val(secret);
    } catch (e) {
        alert('Oh snap!  Error assembling the shares into your secret.  Double check the safe print key maybe?');
    }
}

function scanQr() {
    $('#qrScannerWindow').toggle(true);
    $('#qrScannerWindow').html5_qrcode(function (data) {
            // do something when code is read
            $('#txt2Shares').append(data + '\n');
            scanQrStop();
        },
        function (error) {
            //show read errors
        },
        function (videoError) {
            alert('Error opening stream');
            scanQrStop();
        }
    );
}

function scanQrStop() {
    $('#qrScannerWindow').html5_qrcode_stop();
    $('#qrScannerWindow').html('');
    $('#qrScannerWindow').toggle(false);
}