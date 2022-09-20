const express = require("express");
const request = require("sync-request");
const url = require("url");
const qs = require("qs");
const querystring = require('querystring');
const cons = require('consolidate');
const randomstring = require("randomstring");
const __ = require('underscore');
__.string = require('underscore.string');
const base64url = require('base64url');
const crypto = require('crypto');

const app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
const authServer = {
    authorizationEndpoint: 'http://localhost:9001/authorize',
    tokenEndpoint: 'http://localhost:9001/token'
};

// client information

const client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"]
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;

let access_token = null;
const scope = null;
const refresh_token = null;

let code_verifier = null;

app.get('/', function (req, res) {
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', function (req, res) {

    access_token = null;

    state = randomstring.generate();

    code_verifier = randomstring.generate();
    const conde_challenge = base64url.fromBase64(crypto.createHash('sha256').update(code_verifier).digest('base64'));

    const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
        response_type: 'code',
        client_id: client.client_id,
        redirect_uri: client.redirect_uris[0],
        state: state,
        code_challenge: conde_challenge,
        conde_challenge_method: 'S256'
    });

    console.log("redirect", authorizeUrl);
    res.redirect(authorizeUrl);
});

app.get('/callback', function (req, res) {

    if (req.query.error) {
        // it's an error response, act accordingly
        res.render('error', {error: req.query.error});
        return;
    }

    if (req.query.state !== state) {
        console.log('State DOES NOT MATCH: expected %s got %s', state, req.query.state);
        res.render('error', {error: 'State value did not match'});
        return;
    }

    const code = req.query.code;

    const form_data = qs.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: client.redirect_uris[0],
        code_verifier: code_verifier
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
    };

    const tokRes = request('POST', authServer.tokenEndpoint, {
        body: form_data,
        headers: headers
    });

    console.log('Requesting access token for code %s', code);

    if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
        const body = JSON.parse(tokRes.getBody());

        access_token = body.access_token;
        console.log('Got access token: %s', access_token);

        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
    } else {
        res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
    }
});

app.get('/fetch_resource', function (req, res) {

    if (!access_token) {
        res.render('error', {error: 'Missing Access Token'});
    }

    console.log('Making request with access token %s', access_token);

    const headers = {
        'Authorization': 'Bearer ' + access_token
    };

    const resource = request('POST', protectedResource,
        {headers: headers}
    );

    if (resource.statusCode >= 200 && resource.statusCode < 300) {
        const body = JSON.parse(resource.getBody());
        res.render('data', {resource: body});
        return;
    } else {
        access_token = null;
        res.render('error', {error: resource.statusCode});
        return;
    }


});

const buildUrl = function (base, options, hash) {
    const newUrl = url.parse(base, true);
    delete newUrl.search;
    if (!newUrl.query) {
        newUrl.query = {};
    }
    __.each(options, function (value, key, list) {
        newUrl.query[key] = value;
    });
    if (hash) {
        newUrl.hash = hash;
    }

    return url.format(newUrl);
};

const encodeClientCredentials = function (clientId, clientSecret) {
    return Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

const server = app.listen(9000, 'localhost', function () {
    const host = server.address().address;
    const port = server.address().port;
    console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
