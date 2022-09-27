const express = require("express");
const url = require("url");
const bodyParser = require('body-parser');
const randomstring = require("randomstring");
const cons = require('consolidate');
const nosql = require('nosql').load('database.nosql');
const querystring = require('querystring');
const __ = require('underscore');
__.string = require('underscore.string');

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
let clients = [

    {
        "client_id": "oauth-client-1",
        "client_secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"],
        "scope": "foo bar"
    }
];

let codes = {};

let requests = {};

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
            return;
        }
    } else {
        // user denied access
        const urlParsed = buildUrl(query.redirect_uri, {
            error: 'access_denied'
        });
        res.redirect(urlParsed);
        return;
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

                    return;
                } else {
                    console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
                    res.status(400).json({error: 'invalid_grant'});
                    return;
                }


            } else {
                console.log('Unknown code, %s', req.body.code);
                res.status(400).json({error: 'invalid_grant'});
                return;
            }
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
                        const access_token = randomstring.generate();
                        nosql.insert({access_token: access_token, client_id: clientId});
                        const token_response = {
                            access_token: access_token,
                            token_type: 'Bearer',
                            refresh_token: token.refresh_token
                        };
                        res.status(200).json(token_response);
                        return;
                    } else {
                        console.log('No matching token was found.');
                        res.status(400).json({error: 'invalid_grant'});
                        return;
                    }
                    ;
                })
            });
            break;
        default:
            console.log('Unknown grant type %s', req.body.grant_type);
            res.status(400).json({error: 'unsupported_grant_type'});
            break;
    }
});

const checkClientMetadata = (req, res) => {
    let reg = {};

    reg.token_endpoint_auth_method = !req.body.token_endpoint_auth_method ? 'secret_basic' : req.body.token_endpoint_auth_method;

    if (!__.contains(['secret_basic', 'secret_post', 'none'], reg.token_endpoint_auth_method)) {
        res.status(400).json({error: 'invalid_client_metadata'});
        return;
    }

    if (!req.body.grant_types) {
        if (!req.body.response_types) {
            reg.grant_types = ['authorization_code'];
            reg.response_types = ['code'];
        } else {
            reg.response_types = req.body.response_types;
            reg.grant_types = __.contains(req.body.response_types, 'code') ? ['authorization_code'] : [];
        }
    } else {
        if (!req.body.response_types) {
            reg.grant_types = req.body.grant_types;
            reg.response_types = __.contains(req.body.grant_types, 'authorization_code') ? ['code'] : [];
        } else {
            reg.grant_types = req.body.grant_types;
            reg.response_types = req.body.response_types;
            if (__.contains(req.body.grant_types, 'authorization_code') && !__.contains(req.body.response_types, 'code')) {
                reg.response_types.push('code');
            }
            if (!__.contains(req.body.grant_types, 'authorization_code') && __.contains(req.body.response_types, 'code')) {
                reg.grant_types.push('authorization_code');
            }
        }
    }

    if (!__.isEmpty(__.without(reg.grant_types, 'authorization_code', 'refresh_token')) ||
        !__.isEmpty(__.without(reg.response_types, 'code'))) {
        res.status(400).json({error: 'invalid_client_metadata'});
        return;
    }

    if (!req.body.redirect_uris || !__.isArray(req.body.redirect_uris) || __.isEmpty(req.body.redirect_uris)) {
        res.status(400).json({error: 'invalid_redirect_uri'});
        return;
    } else {
        reg.redirect_uris = req.body.redirect_uris;
    }

    if (typeof (req.body.client_name) == 'string') {
        reg.client_name = req.body.client_name;
    }

    if (typeof (req.body.client_uri) == 'string') {
        reg.client_uri = req.body.client_uri;
    }

    if (typeof (req.body.logo_uri) == 'string') {
        reg.logo_uri = req.body.logo_uri;
    }

    if (typeof (req.body.scope) == 'string') {
        reg.scope = req.body.scope;
    }

    return reg;
};

app.post('/register', (req, res) => {

    const reg = checkClientMetadata(req, res);
    if (!reg) {
        return;
    }

    reg.client_id = randomstring.generate();
    if (__.contains(['client_secret_basic', 'client_secret_post']), reg.token_endpoint_auth_method) {
        reg.client_secret = randomstring.generate();
    }

    reg.client_id_created_at = Math.floor(Date.now() / 1000);
    reg.client_secret_expires_at = 0;

    reg.registration_access_token = randomstring.generate();
    reg.registration_client_uri = 'http://localhost:9001/register/' + reg.client_id;

    clients.push(reg);

    res.status(201).json(reg);

});

const authorizeConfigurationEndpointRequest = (req, res, next) => {
    const clientId = req.params.clientId;
    const client = getClient(clientId);
    if (!client) {
        res.status(404).end();
        return;
    }

    const auth = req.headers['authorization'];
    if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
        const regToken = auth.slice('bearer '.length);

        if (regToken === client.registration_access_token) {
            req.client = client;
            next();
        } else {
            res.status(403).end();
        }

    } else {
        res.status(401).end();
    }

};

app.get('/register/:clientId', authorizeConfigurationEndpointRequest, (req, res) => {
    res.status(200).json(req.client);
});

app.put('/register/:clientId', authorizeConfigurationEndpointRequest, (req, res) => {

    if (req.body.client_id !== req.client.client_id) {
        res.status(400).json({error: 'invalid_client_metadata'});
        return;
    }

    if (req.body.client_secret && req.body.client_secret !== req.client.client_secret) {
        res.status(400).json({error: 'invalid_client_metadata'});
    }

    const reg = checkClientMetadata(req, res);
    if (!reg) {
        return;
    }

    __.each(reg, (value, key, list) => {
        req.client[key] = reg[key];
    });

    res.status(200).json(req.client);
});

app.delete('/register/:clientId', authorizeConfigurationEndpointRequest, (req, res) => {
    clients = __.reject(clients, __.matches({client_id: req.client.client_id}));

    nosql.remove().make(builder => {
        builder.where('client_id', req.client.client_id);
        builder.callback((err, count) => {
            console.log("Removed %s tokens", count);
        });
    });

    res.status(204).end();
});

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

const decodeClientCredentials = auth => {
    const clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
    const clientId = querystring.unescape(clientCredentials[0]);
    const clientSecret = querystring.unescape(clientCredentials[1]);
    return {id: clientId, secret: clientSecret};
};

const getScopesFromForm = body => __.filter(__.keys(body),
    s => __.string.startsWith(s, 'scope_'))
    .map(s => s.slice('scope_'.length));

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

const server = app.listen(9001, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
