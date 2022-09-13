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
const clients = [
    {
        "client_id": "oauth-client-1",
        "client_secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"]
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
        res.render('error', {error: 'Invalid redirect URI'});
    } else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
        console.log('Unmatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
        res.render('error', {error: 'Invalid redirect URI'});
    } else {
        const reqid = randomstring.generate(8);
        requests[reqid] = req.query;
        res.render('approve', {client: client, reqid: reqid});
    }
});

app.post('/approve', (req, res) => {
    const reqid = req.body.reqid;
    const query = requests[reqid];
    if (!query) {
        // there was no matched saved request, this is an error
        res.render('error', {error: 'No matching authorization request'});
    }
    if (req.body.approve) {
        if (query.response_type === 'code') {
            // user approved access
            const code = randomstring.generate(8);
            // save the code and request for later
            codes[code] = {request: query};

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
    let clientId = null;
    let clientSecret = null;
    if (auth) {
        // check the auth header
        const clientCredentials = decodeClientCredentials(auth);
        clientId = clientCredentials.id;
        clientSecret = clientCredentials.secret;
    }
    // otherwise, check the post body
    if (req.body.client_id) {
        if (clientId !== null) {
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

    if (req.body.grant_type === 'authorization_code') {
        const code = codes[req.body.code];
        if (code) {
            delete codes[req.body.code];
            if (code.request.client_id === clientId) {
                const access_token = randomstring.generate(8);
                nosql.insert({access_token: access_token, client_id: clientId});

                console.log('Issuing access token %s', access_token);
                const token_response = {access_token: access_token, token_type: 'Bearer'};
                res.status(200).json(token_response);
                console.log('Issued tokens for code %s', req.body.code);
            } else {
                res.status(400).json({error: 'invalid_grant'});
            }
        } else {
            res.status(400).json({error: 'invalid_grant'});
        }
    } else {
        res.status(400).json({error: 'unsupported_grant_type'});
    }
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

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

const server = app.listen(9001, 'localhost', () => {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
