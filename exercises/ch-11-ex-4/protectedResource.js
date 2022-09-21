const express = require("express");
const bodyParser = require('body-parser');
const cons = require('consolidate');
const qs = require("qs");
const querystring = require('querystring');
const request = require("sync-request");
const __ = require('underscore');
const cors = require('cors');

const app = express();

app.use(bodyParser.urlencoded({extended: true})); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

const resource = {
    "name": "Protected Resource",
    "description": "This data has been protected by OAuth 2.0"
};

const protectedResources = {
    "resource_id": "protected-resource-1",
    "resource_secret": "protected-resource-secret-1"
};

const authServer = {
    introspectionEndpoint: 'http://localhost:9001/introspect'
};


const getAccessToken = (req, res, next) => {
    // check the auth header first
    const auth = req.headers['authorization'];
    let inToken = null;
    if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
        inToken = auth.slice('bearer '.length);
    } else if (req.body && req.body.access_token) {
        // not in the header, check in the form body
        inToken = req.body.access_token;
    } else if (req.query && req.query.access_token) {
        inToken = req.query.access_token
    }

    console.log('Incoming token: %s', inToken);

    const formData = qs.stringify({token: inToken});
    const headers = {
        'Content-Type': 'application/x-www.form-urlencoded',
        'Authorization': 'Basic ' + encodeClientCredentials(protectedResources.resource_id, protectedResources.resource_secret)
    };
    const tokRes = request('POST', authServer.introspectionEndpoint, {
        body: formData,
        headers: headers
    });

    if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
        const body = JSON.parse(tokRes.getBody());
        console.log('Got introspection response', body);
        const active = body.active;

        if (active) {
            req.access_token = body;
        }
    }
    next();
};

const requireAccessToken = (req, res, next) => {
    if (req.access_token) {
        next();
    } else {
        res.status(401).end();
    }
};


app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, (req, res) => {

    if (req.access_token) {
        res.json(resource);
    } else {
        res.status(401).end();
    }

});

const encodeClientCredentials = (clientId, clientSecret) => Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');

const server = app.listen(9002, 'localhost', function () {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
