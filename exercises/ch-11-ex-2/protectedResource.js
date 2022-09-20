const express = require("express");
const bodyParser = require('body-parser');
const cons = require('consolidate');
const base64url = require('base64url');
const cors = require('cors');
const jose = require('jsrsasign');

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


const sharedTokenSecret = 'shared OAuth token secret!';


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

    const tokenParts = inToken.split('.');
    const header = JSON.parse(base64url.decode(tokenParts[0]));
    const payload = JSON.parse(base64url.decode(tokenParts[1]));
    console.log('Payload', payload);

    if (jose.jws.JWS.verify(inToken, new Buffer(sharedTokenSecret).toString('hex'), [header.alg])) {

        if (payload.iss === 'http://localhost:9001/') {
            console.log('issuer OK');
            if ((Array.isArray(payload.aud) && __.contains(payload.aud, 'http://localhost:9002/')) ||
                payload.aud === 'http://localhost:9002/') {
                console.log('Audience OK');

                const now = Math.floor(Date.now() / 1000);

                if (payload.iat <= now) {
                    console.log('issued-at OK');
                    if (payload.exp >= now) {
                        console.log('expiration OK');

                        console.log('Token valid!');

                        req.access_token = payload;

                    }
                }
            }
        }

    }

    next();


};

const requireAccessToken = function (req, res, next) {
    if (req.access_token) {
        next();
    } else {
        res.status(401).end();
    }
};


const savedWords = [];

app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, function (req, res) {

    if (req.access_token) {
        res.json(resource);
    } else {
        res.status(401).end();
    }

});

const server = app.listen(9002, 'localhost', function () {
    const host = server.address().address;
    const port = server.address().port;

    console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
