const express = require("express");
const path = require("path");

const app = express();

app.set('view engine', 'html');
app.set('views', 'files/client');

app.use('/', express.static('files/client'));

const server = app.listen(9000, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;
    console.log('OAuth Client is listening at http://%s:%s', host, port);
});

app.get("/*", function(req, res){
	res.sendFile(path.join(__dirname, "files/client/index.html"));
});
