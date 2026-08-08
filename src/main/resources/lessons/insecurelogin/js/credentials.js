function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
	//credentials are verified on the server, they are never shipped to the browser
	//nor sent back in clear text, so there is nothing to read from the traffic
	xhttp['send']()
}
