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

const client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"],
    "scope": "openid profile email phone address"
};

// authorization server information
const authServer = {
    server: 'http://localhost:9001/',
    authorizationEndpoint: 'http://localhost:9001/authorize',
    tokenEndpoint: 'http://localhost:9001/token',
    userInfoEndpoint: 'http://localhost:9002/userinfo'
};

const rsaKey = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;

let access_token = null;
let refresh_token = null;
let scope = null;
let id_token = null;
let userInfo = null;

app.get('/', (req, res) => {
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', (req, res) => {

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

        if (body.id_token) {
            userInfo = null;
            id_token = null;

            console.log('Got ID Token: %s', body.id_token);

            // check the id token
            const pubKey = jose.KEYUTIL.getKey(rsaKey);
            const tokenParts = body.id_token.split('.');
            const payload = JSON.parse(base64url.decode(tokenParts[1]));
            console.log('Payload', payload);
            if (jose.jws.JWS.verify(body.id_token, pubKey, [rsaKey.alg])) {
                console.log('Signature validated.');
                if (payload.iss === authServer.server) {
                    console.log('Issuer OK');
                    if (Array.isArray(payload.aud) && __.contains(payload.aud, client.client_id) || (payload.aud === client.client_id)) {
                        console.log('Audience OK');

                        const now = Math.floor(Date.now() / 1000);

                        if (payload.iat <= now) {
                            console.log('issued-at OK');
                            if (payload.exp >= now) {
                                console.log('expiration OK');

                                console.log('Token valid!');

                                // save just the payload, not the container (which has been validated)
                                id_token = payload;
                            }
                        }
                    }
                }
            }
            res.render('userinfo', {userInfo: userInfo, id_token: id_token});
            return;
        }

        res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});

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
        res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
    }

});

app.get('/userinfo', (req, res) => {

    /*
     * Call the UserInfo endpoint and store/display the results
     */

});

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
 
