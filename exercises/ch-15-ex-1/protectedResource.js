const express = require("express");
const bodyParser = require('body-parser');
const cons = require('consolidate');
const qs = require("qs");
const querystring = require('querystring');
const request = require("sync-request");
const __ = require('underscore');
const base64url = require('base64url');
const jose = require('jsrsasign');
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

const protectedResource = {
    "resource_id": "protected-resource-1",
    "resource_secret": "protected-resource-secret-1"
};

const authServer = {
    introspectionEndpoint: 'http://localhost:9001/introspect'
};


const getAccessToken = (req, res, next) => {
    let inToken = null;
    const auth = req.headers['authorization'];
    if (auth && auth.toLowerCase().indexOf('pop') === 0) {
        inToken = auth.slice('pop '.length);
    } else if (req.body && req.body.pop_access_token) {
        inToken = req.body.pop_access_token;
    } else if (req.query && req.query.pop_access_token) {
        inToken = req.query.pop_access_token;
    }

    console.log('Incoming PoP: %s', inToken);

    const tokenParts = inToken.toString().split('.');
    const header = JSON.parse(base64url.decode(tokenParts[0]));
    const payload = JSON.parse(base64url.decode(tokenParts[1]));
    const at = payload.at;

    const form_data = qs.stringify({
        token: at
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + encodeClientCredentials(protectedResource.resource_id, protectedResource.resource_secret)
    };
    const tokRes = request('POST', authServer.introspectionEndpoint, {
        body: form_data,
        headers: headers
    });
    if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
        const body = JSON.parse(tokRes.getBody());

        console.log('Got introspection response', body);

        const active = body.active;

        if (active) {
            const publicKey = jose.KEYUTIL.getKey(body.access_token_key);
            if (jose.jws.JWS.verify(inToken, publicKey, [header.alg])) {
                console.log('Signature is valid');

                if ((!payload.m || payload === req.method) &&
                    (!payload.u || payload.u === 'localhost:9002') &&
                    (!payload.p || payload.p === req.path)) {
                    console.log('All components matched');

                    req.access_token = {
                        access_token: at,
                        scope: body.scope
                    };
                }
            }
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

const server = app.listen(9002, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
