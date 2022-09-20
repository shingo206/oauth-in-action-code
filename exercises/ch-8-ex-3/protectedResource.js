const express = require("express");
const url = require("url");
const bodyParser = require('body-parser');
const randomstring = require("randomstring");
const cons = require('consolidate');
const nosql = require('nosql').load('database.nosql');
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

const resource = {
    "name": "Protected Resource",
    "description": "This data has been protected by OAuth 2.0"
};

const sharedTokenSecret = "shared token secret!";

const rsaKey = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
};

const protectedResources = {
    "resource_id": "protected-resource-1",
    "resource_secret": "protected-resource-secret-1"
};

const authServer = {
    introspectionEndpoint: 'http://localhost:9001/introspect'
};


const getAccessToken = function (req, res, next) {
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
    nosql.one().make(builder => {
        builder.where('access_token', inToken);
        builder.callback(function (err, token) {
            if (token) {
                console.log("We found a matching token: %s", inToken);
            } else {
                console.log('No matching token was found.');
            }
            ;
            req.access_token = token;
            next();
        });
    });
};

const requireAccessToken = (req, res, next) => {
    if (req.access_token) {
        next();
    } else {
        res.status(401).end();
    }
};

app.options('/helloWorld', cors());

app.get("/helloWorld", cors(), getAccessToken, (req, res) => {
    if (req.access_token) {

        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31636000');

        const resource = {
            "greeting": ""
        };

        switch (req.query.language) {
            case "en":
                resource.greeting = 'Hello World';
                break;
            case "de":
                resource.greeting = 'Hallo Welt';
                break;
            case "it":
                resource.greeting = 'Ciao Mondo';
                break;
            case "fr":
                resource.greeting = 'Bonjour monde';
                break;
            case "es":
                resource.greeting = 'Hola mundo';
                break;
            default:
                resource.greeting = "Error, invalid language: " + qs.stringify(req.query.language);
                break;
        }
        res.json(resource);
    }
});

const server = app.listen(9002, 'localhost', function () {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
