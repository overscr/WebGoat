function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
    // The credentials themselves are never written into this script anymore - the server
    // holds them and the login exchange carries them over the (unencrypted) wire instead.
    // Sniff the request/response with a packet capture tool or the browser's Network tab
    // to read it, exactly like a real attacker eavesdropping on plaintext HTTP would.
    xhttp['send']();
}
