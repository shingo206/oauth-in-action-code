const express = require("express");
const bodyParser = require('body-parser');
const request = require("sync-request");
const url = require("url");
const qs = require("qs");
const querystring = require('querystring');
const cons = require('consolidate');
const randomstring = require("randomstring");
const jose = require('jsrsasign');
const base64url = require('base64url');
const __ = require('underscore');
__.string = require('underscore.string');


const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// client information

let client = {};

// authorization server information
const authServer = {
    authorizationEndpoint: 'http://localhost:9001/authorize',
    tokenEndpoint: 'http://localhost:9001/token',
    registrationEndpoint: 'http://localhost:9001/register'
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;

let access_token = null;
let refresh_token = null;
let scope = null;

app.get('/', (req, res) => {
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, client: client});
});

app.get('/authorize', (req, res) => {

    if (!client.client_id) {
        registerClient();
        if (!client.client_id) {
            res.render('error', {error: 'Unable to register client.'});
            return;
        }
    }

    access_token = null;
    refresh_token = null;
    scope = null;
    state = randomstring.generate();

    const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
        response_type: 'code',
        scope: client.scope,
        client_id: client.client_id,
        redirect_uri: client.redirect_uris[0],
        state: state
    });

    console.log("redirect", authorizeUrl);
    res.redirect(authorizeUrl);
});

app.get("/callback", (req, res) => {

    if (req.query.error) {
        // it's an error response, act accordingly
        res.render('error', {error: req.query.error});
        return;
    }

    const resState = req.query.state;
    if (resState === state) {
        console.log('State value matches: expected %s got %s', state, resState);
    } else {
        console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
        res.render('error', {error: 'State value did not match'});
        return;
    }

    const code = req.query.code;

    const form_data = qs.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: client.redirect_uris[0]
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
    };

    const tokRes = request('POST', authServer.tokenEndpoint,
        {
            body: form_data,
            headers: headers
        }
    );

    console.log('Requesting access token for code %s', code);

    if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
        const body = JSON.parse(tokRes.getBody());

        access_token = body.access_token;
        console.log('Got access token: %s', access_token);
        if (body.refresh_token) {
            refresh_token = body.refresh_token;
            console.log('Got refresh token: %s', refresh_token);
        }

        scope = body.scope;
        console.log('Got scope: %s', scope);

        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, client: client});

    } else {
        res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
    }
});

app.get('/fetch_resource', (req, res) => {

    if (!access_token) {
        res.render('error', {error: 'Missing access token.'});
        return;
    }

    console.log('Making request with access token %s', access_token);

    const headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/x-www-form-urlencoded'
    };

    const resource = request('POST', protectedResource,
        {headers: headers}
    );

    if (resource.statusCode >= 200 && resource.statusCode < 300) {
        const body = JSON.parse(resource.getBody());
        res.render('data', {resource: body});

    } else {
        access_token = null;
        if (refresh_token) {
            // try to refresh and start again
            refreshAccessToken(req, res);

        } else {
            res.render('error', {error: 'Server returned response code: ' + resource.statusCode});

        }
    }

});

const registerClient = () => {
    const template = {
        client_name: 'Oauth in Action Dynamic Test Client',
        client_url: 'http://localhost:9000/',
        redirect_uris: ['http://localhost:9000/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
        scope: 'foo bar'
    };
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    const regRes = request('POST', authServer.registrationEndpoint, {
        body: JSON.stringify(template),
        headers: headers
    });

    if (regRes.statusCode === 201) {
        const body = JSON.parse(regRes.getBody());
        console.log('Got registered client', body);
        if (body.client_id) {
            client = body;
        }
    }
};

app.use('/', express.static('files/client'));

const buildUrl = (base, options, hash) => {
    const newUrl = url.parse(base, true);
    delete newUrl.search;
    if (!newUrl.query) {
        newUrl.query = {};
    }
    __.each(options, (value, key, list) => {
        newUrl.query[key] = value;
    });
    if (hash) {
        newUrl.hash = hash;
    }

    return url.format(newUrl);
};

const encodeClientCredentials = (clientId, clientSecret) => Buffer.from(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');

const server = app.listen(9000, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;
    console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
