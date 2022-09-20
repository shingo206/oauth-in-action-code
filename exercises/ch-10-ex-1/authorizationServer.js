const express = require("express");
const url = require("url");
const bodyParser = require('body-parser');
const randomstring = require("randomstring");
const cons = require('consolidate');
const nosql = require('nosql').load('database.nosql');
const querystring = require('querystring');
const __ = require('underscore');
__.string = require('underscore.string');
const base64url = require('base64url');
const crypto = require('crypto');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true})); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
const authServer = {
    authorizationEndpoint: 'http://localhost:9001/authorize',
    tokenEndpoint: 'http://localhost:9001/token'
};

// client information
const clients = [

    {
        "client_id": "oauth-client-1",
        "client_secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"],
        "scope": "foo bar"
    }
];

const codes = {};

const requests = {};

const getClient = clientId => __.find(clients, client => client.client_id === clientId);

app.get('/', (req, res) => {
    res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", (req, res) => {

    const client = getClient(req.query.client_id);

    if (!client) {
        console.log('Unknown client %s', req.query.client_id);
        res.render('error', {error: 'Unknown client'});
    } else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
        console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
        res.render('error', {error: 'Invalid redirect URI'});
    } else {

        const rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
        const cscope = client.scope ? client.scope.split(' ') : undefined;
        if (__.difference(rscope, cscope).length > 0) {
            const urlParsed = buildUrl(req.query.redirect_uri, {
                error: 'invalid_scope'
            });
            res.redirect(urlParsed);
            return;
        }

        const reqid = randomstring.generate(8);

        requests[reqid] = req.query;

        res.render('approve', {client: client, reqid: reqid, scope: rscope});
    }

});

app.post('/approve', (req, res) => {

    const reqid = req.body.reqid;
    const query = requests[reqid];
    delete requests[reqid];

    if (!query) {
        // there was no matching saved request, this is an error
        res.render('error', {error: 'No matching authorization request'});
        return;
    }

    if (req.body.approve) {
        if (query.response_type === 'code') {
            // user approved access

            const rscope = getScopesFromForm(req.body);
            const client = getClient(query.client_id);
            const cscope = client.scope ? client.scope.split(' ') : undefined;
            if (__.difference(rscope, cscope).length > 0) {
                const urlParsed = buildUrl(query.redirect_uri, {
                    error: 'invalid_scope'
                });
                res.redirect(urlParsed);
                return;
            }

            const code = randomstring.generate(8);

            // save the code and request for later

            codes[code] = {request: query, scope: rscope};

            const urlParsed = buildUrl(query.redirect_uri, {
                code: code,
                state: query.state
            });
            res.redirect(urlParsed);
        } else {
            // we got a response type we don't understand
            const urlParsed = buildUrl(query.redirect_uri, {
                error: 'unsupported_response_type'
            });
            res.redirect(urlParsed);
        }
    } else {
        // user denied access
        const urlParsed = buildUrl(query.redirect_uri, {
            error: 'access_denied'
        });
        res.redirect(urlParsed);
    }

});

app.post("/token", (req, res) => {

    const auth = req.headers['authorization'];
    let clientId = null, clientSecret = null;
    if (auth) {
        // check the auth header
        const clientCredentials = decodeClientCredentials(auth);
        clientId = clientCredentials.id;
        clientSecret = clientCredentials.secret;
    }

    // otherwise, check the post body
    if (req.body.client_id) {
        if (clientId) {
            // if we've already seen the client's credentials in the authorization header, this is an error
            console.log('Client attempted to authenticate with multiple methods');
            res.status(401).json({error: 'invalid_client'});
            return;
        }

        clientId = req.body.client_id;
        clientSecret = req.body.client_secret;
    }

    const client = getClient(clientId);
    if (!client) {
        console.log('Unknown client %s', clientId);
        res.status(401).json({error: 'invalid_client'});
        return;
    }

    if (client.client_secret !== clientSecret) {
        console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
        res.status(401).json({error: 'invalid_client'});
        return;
    }

    switch (req.body.grant_type) {
        case 'authorization_code':
            const code = codes[req.body.code];

            if (code) {
                delete codes[req.body.code]; // burn our code, it's been used
                if (code.request.client_id === clientId) {

                    if (code.request.code_challenge) {
                        console.log('Testing challenge %s against verifier %s', code.request.code_challenge, req.body.code_verifier);
                        let code_challenge = null;
                        switch (code.request.code_challenge_method) {
                            case "plain":
                                code_challenge = req.body.code_challenge;
                                break;
                            case "S256":
                                code_challenge = base64url
                                    .fromBase64(crypto.createHash('sha256')
                                        .update(req.body.code_challenge)
                                        .digest('base64'));
                                break;
                            default:
                                console.log('Unknown code challenge method', code.request.code_challenge_method);
                                res.status(400).json({error: 'invalid_request'});
                                return;
                        }
                        if (code.request.code_challenge !== code_challenge) {
                            console.log('Code challenge did not matched, expected %s got %s', code.request.code_challenge, req.body.code_challenge);
                            res.status(400).json({error: 'invalid_request'});
                            return;
                        }
                    }

                    const access_token = randomstring.generate();
                    const refresh_token = randomstring.generate();

                    nosql.insert({access_token: access_token, client_id: clientId, scope: code.scope});
                    nosql.insert({refresh_token: refresh_token, client_id: clientId, scope: code.scope});

                    console.log('Issuing access token %s', access_token);

                    const token_response = {
                        access_token: access_token,
                        token_type: 'Bearer',
                        refresh_token: refresh_token,
                        scope: code.scope.join(' ')
                    };

                    res.status(200).json(token_response);
                    console.log('Issued tokens for code %s', req.body.code);

                } else {
                    console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
                    res.status(400).json({error: 'invalid_grant'});
                }


            } else {
                console.log('Unknown code, %s', req.body.code);
                res.status(400).json({error: 'invalid_grant'});
                return;
            }
            break;
        case 'refresh_token':
            nosql.one().make(builder => {
                builder.where('refresh_token', req.body.refresh_token);
                builder.callback((err, token) => {
                    if (token) {
                        console.log("We found a matching refresh token: %s", req.body.refresh_token);
                        if (token.client_id !== clientId) {
                            nosql.remove().make(builder => {
                                builder.where('refresh_token', req.body.refresh_token);
                            });
                            res.status(400).json({error: 'invalid_grant'});
                            return;
                        }

                        /*
                         * Bonus: handle scopes for a refresh token request appropriately
                         */

                        const access_token = randomstring.generate();
                        nosql.insert({access_token: access_token, client_id: clientId});
                        const token_response = {
                            access_token: access_token,
                            token_type: 'Bearer',
                            refresh_token: token.refresh_token
                        };
                        res.status(200).json(token_response);
                    } else {
                        console.log('No matching token was found.');
                        res.status(400).json({error: 'invalid_grant'});
                    }
                })
            });
            break;
        default:
            console.log('Unknown grant type %s', req.body.grant_type);
            res.status(400).json({error: 'unsupported_grant_type'});
            break;
    }
});

const buildUrl = (base, options, hash) => {
    const newUrl = url.parse(base, true);
    delete newUrl.search;
    if (!newUrl.query) {
        newUrl.query = {};
    }
    __.each(options, (value, key) => {
        newUrl.query[key] = value;
    });
    if (hash) {
        newUrl.hash = hash;
    }

    return url.format(newUrl);
};

const decodeClientCredentials = auth => {
    const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
    const clientId = querystring.unescape(clientCredentials[0]);
    const clientSecret = querystring.unescape(clientCredentials[1]);
    return {id: clientId, secret: clientSecret};
};

const getScopesFromForm = body => __.filter(__.keys(body), s => __.string.startsWith(s, 'scope_'))
    .map(s => s.slice('scope_'.length));

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

const server = app.listen(9001, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
