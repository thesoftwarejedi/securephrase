
function hex2str(str) {
    return secrets.hex2str(str);
}

function str2hex(str) {
    return secrets.str2hex(str);
}

function hex2b64(str) {
    var tmp = hex2asc(str);
    return btoa(tmp);
}

function b642hex(str) {
    var tmp = atob(str);
    return asc2hex(tmp);
}

function hex2asc(inputstr) {
    var outputstr = '';
    inputstr = inputstr.replace(/^(0x)?/g, '');
    inputstr = inputstr.replace(/[^A-Fa-f0-9]/g, '');
    inputstr = inputstr.split('');
    for(var i=0; i<inputstr.length; i+=2) {
        outputstr += String.fromCharCode(parseInt(inputstr[i]+''+inputstr[i+1], 16));
    }
    return outputstr;
}

function asc2hex(inputstr) {
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