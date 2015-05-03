/**
 * Created by dana on 5/2/15.
 */

function generateShares() {
    var seed = document.getElementById('txt1Secret').value;
    var numShares = parseInt(document.getElementById('txt1NumShares').value);
    var numRequired = parseInt(document.getElementById('txt1NumRequired').value);

    var seedHex = secrets.str2hex(seed);
    var shares = secrets.share(seedHex, numShares, numRequired);
    var divShares = document.getElementById('div1Shares');
    for (var i = 0; i < shares.length; i++) {
        shares[i] = shares[i].substring(1); //knock the leading '8' off
        divShares.innerHTML = divShares.innerHTML + '<span class="share-text">' + hexToBase64(shares[i]) + '</span><div class="share-qr-code" id="share' + i + '"></div>';
    }
    for (var i = 0; i < shares.length; i++) {
        new QRCode(document.getElementById('share' + i), { text: hexToBase64(shares[i]), correctLevel: QRCode.CorrectLevel.L });
    }
}

function recoverShares() {
    var shares = document.getElementById('txt2Shares').value;
    var sharesArray = shares.split('\n');
    for (var i = 0; i < sharesArray.length; i++) {
        sharesArray[i] = '8' + base64ToHex(sharesArray[i]);
    }
    var hexSecret = secrets.combine(sharesArray);
    var secret = secrets.hex2str(hexSecret);
    document.getElementById('txt2Secret').value = secret;
}

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