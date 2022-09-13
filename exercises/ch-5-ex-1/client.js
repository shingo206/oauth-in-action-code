const express = require("express");
const bodyParser = require('body-parser');
const request = require("sync-request");
const url = require("url");
const qs = require("qs");
const querystring = require('querystring');
const cons = require('consolidate');
const randomstring = require("randomstring");

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
const authServer = {
    authorizationEndpoint: 'http://localhost:9001/authorize',
    tokenEndpoint: 'http://localhost:9001/token',
    revocationEndpoint: 'http://localhost:9001/revoke',
    registrationEndpoint: 'http://localhost:9001/register',
    userInfoEndpoint: 'http://localhost:9001/userinfo'
};

// client information

const client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"],
    "scope": ""
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;

let access_token = null;
let refresh_token = null;
let scope = null;

app.get('/', (req, res) => {
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', (req, res) => {

    access_token = null;
    refresh_token = null;
    scope = null;
    state = randomstring.generate();

    const authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
    delete authorizeUrl.search; // this is to get around odd behavior in the node URL library
    authorizeUrl.query.response_type = 'code';
    authorizeUrl.query.scope = client.scope;
    authorizeUrl.query.client_id = client.client_id;
    authorizeUrl.query.redirect_uri = client.redirect_uris[0];
    authorizeUrl.query.state = state;

    console.log("redirect", url.format(authorizeUrl));
    res.redirect(url.format(authorizeUrl));
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
        redirect_uri: client.redirect_uri
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
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

        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
    } else {
        res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
    }
});

const refreshAccessToken = (req, res) => {
    const form_data = qs.stringify({
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        client_id: client.client_id,
        client_secret: client.client_secret,
        redirect_uri: client.redirect_uri
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    };
    console.log('Refreshing token %s', refresh_token);
    const tokRes = request('POST', authServer.tokenEndpoint,
        {
            body: form_data,
            headers: headers
        }
    );
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

        // try again
        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
    } else {
        console.log('No refresh token, asking the user to get a new access token');
        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
    }
};

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
        return;
    } else {
        access_token = null;
        res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
        return;
    }

});

app.use('/', express.static('files/client'));

const server = app.listen(9000, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;
    console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
