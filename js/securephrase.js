/**
 * Created by dana on 5/2/15.
 */

//have to explicitly set because secrets.js uses require === 'function' to detect node
//and bitcore defines 'require' so they can be lazy and use it on the browser
var tempRequire = require;
require = null;
secrets.setRNG(); //set while require == null
require = tempRequire;

function generateShares() {
    var secret = $('#txt1Secret').val();
    var numShares = parseInt($('#txt1NumShares').val());
    var numRequired = parseInt($('#txt1NumRequired').val());

    var secretHex = asc2hex(secret);
    $('#txt1SecretHex').val(secretHex);

    var shares = secrets.share(secretHex, numShares, numRequired);
    var divShares = $('#div1Shares');
    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1);
        divShares.append('<span class="share-text">' + hex2b64(shares[i]) + '</span><div class="share-qr-code" id="share' + i + '" />');
    }
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('share' + i), { text: hex2b64(shares[i]), correctLevel: QRCode.CorrectLevel.M });
    }
}

function recoverShares() {
    var shares = $('#txt2Shares').val();
    var sharesArray = shares.split('\n');
    for (var i = 0; i < sharesArray.length; i++) {
        sharesArray[i] = '8' + b642hex(sharesArray[i]);
    }
    var hexSecret = secrets.combine(sharesArray);
    var secret = hex2asc(hexSecret);
    $('#txt2Secret').val(secret);
}
