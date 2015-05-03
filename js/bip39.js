/**
 * Created by dana on 5/2/15.
 */

function validatePhrase() {
    var isValid = Mnemonic.isValid($('#txt1Secret').val());
    $('.phrase-valid').toggle(isValid);
    $('.phrase-invalid').toggle(!isValid);
}

function generateShares() {
    var seed = $('#txt1Secret').val();
    var numShares = parseInt($('#txt1NumShares').val());
    var numRequired = parseInt($('#txt1NumRequired').val());

    var seedHex = secrets.str2hex(seed);
    var shares = secrets.share(seedHex, numShares, numRequired);
    var divShares = $('#div1Shares');
    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1); //knock the leading '8' off
        divShares.innerHTML = divShares.innerHTML + '<span class="share-text">' + hexToBase64(shares[i]) + '</span><div class="share-qr-code" id="share' + i + '"></div>';
    }
    for (var i = 0; i < shares.length; i++) {
        new QRCode($('#share' + i), { text: hexToBase64(shares[i]), correctLevel: QRCode.CorrectLevel.L });
    }
}

function recoverShares() {
    var shares = $('#txt2Shares').val();
    var sharesArray = shares.split('\n');
    for (var i = 0; i < sharesArray.length; i++) {
        sharesArray[i] = '8' + base64ToHex(sharesArray[i]);
    }
    var hexSecret = secrets.combine(sharesArray);
    var secret = secrets.hex2str(hexSecret);
    $('#txt2Secret').val() = secret;
}

/**
 *
 * helper functions, no outside entry
 *
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