## Synopsis

A web page which allows you to secure a secret using [Shamir's Secret Sharing](http://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) algorithm to split a secret phrase into a number of shares, then allow easy reconstruction of that secret with a just a subset of those shares.

Each share contains no hints at the contents of the secret, even when combined with other shares until the full number of required shares is reached.  This allows you to split short yet important data across any number of people or hiding places more securely and without trust of any single entity.

## Usage

#### Online version
An online version of this site has been deployed here: http://thesoftwarejedi.github.io/securephrase/.  It is suggested that the page is downloaded for offline use if being used for high security purposes.

#### Opening
Dowload the contents of the "dist" folder into a local directory, and open "index.html" in a browser.  This page can, and is suggested to be, run on an offline computer for maximum security.  At the very least, run your browser in an incognito window, or launch it without extensions running.

#### Splitting a secret
You can enter something important, such as a bitcoin private key, mnemonic, or password and instructions for using it into the "secret" box on the "Split" tab.  *Note that Choose the number of shares you'd like it to be split into, and the number of shares required to reconstruct it.  After pressing "Generate", you'll be presented with a number of text strings and corresponding QR codes.  The QR codes contain the same data as the text strings.

When printing, the shares will be conveniently separated onto multiple pages to accomodate being stored separately, and only the QR codes are printed.  It is not expected to print the large text strings.  Instead of printing, the shares' text can be copied, pasted, and sent out by other methods.

#### Recovering a secret
On the "Recover" tab, you can enter the shares which you have in the "Shares" text box, each on a separate line.  Alternatively, there is a QR reader which works in modern browsers to scan the QR code.  If the browser scanner does not work, a smart phone scanner will work, then the text can be copied and sent to the website by whatever means possible.  Upon pressing the "Recover" button, the secret will be reconstructed if enough shares are presented.

#### Advanced
If printing on an untrusted printed (or any printer if you're insanely risk adverse - printers do save things they print...), you can use the "Safe Print" option to encrypt each share with a random passphrase which **is not printed**.  This passphrase should be handwritten on the share printouts after printing, and provided in the appropriate textbox during recovery.

#### Example Use

Split into 2 of 3 shares: Keep the shares hidden in discrete, physically separated locations.  This protects your backup from physical loss of one of the locations.

Split into 4 of 8 shares: give shares to a relative, two close (yet disparate) friends, your lawyer, a bank vault, store two at home, and one at the office.  By requiring four of eight shares to reconstruct your secret, you're able to do so if needed with minimal assistance, yet any of the other parties would have to collude and/or have access and knowledge of all the shares locations.  In the event you are incapacitated, your lawyer or the parties should be able to coordinate access to the remaining shares.

## Motivation

This was created as a secure way to store my TREZOR device BIP39 mnemonic phrase, which is required to restore my Bitcoin funds in the event of loss.  This method of backing up my phrase allows it to be safe from disaster at home which would result in the loss of any physical backup, or if an unforseen event happens to me which causes me to not remember the phrase, or where it is stored.

## Building

    bower install
    grunt
    open dist/index.html

## Tests

It's probably super important to have some of these.  I'd love someone experienced in creating javascript tests to take this on.

## Contributors

Fork and do anything you like; create issues for requests - even things you're enhancing so I know where you're at and it opens the discussion.

## License

MIT License
