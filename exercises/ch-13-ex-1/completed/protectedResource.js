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

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

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

const getAccessToken = (req, res, next) => {
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
	  builder.callback((err, token) => {
	    if (token) {
	      console.log("We found a matching token: %s", inToken);
	    } else {
	      console.log('No matching token was found.');
	    }
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

app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, (req, res) => {
	console.log(req.access_token);
	if (req.access_token) {
		res.json(resource);
	} else {
		res.status(401).end();
	}

});

const userInfoEndpoint = (req, res) => {

	if (!__.contains(req.access_token.scope, 'openid')) {
		res.status(403).end();
		return;
	}

	const user = req.access_token.user;
	if (!user) {
		res.status(404).end();
		return;
	}

	const out = {};
	__.each(req.access_token.scope, scope => {
        const user_info_out = options => {
            __.each(options, claim => {
                if (user[claim]) {
                    out[claim] = user[claim];
                }
            });
        };

        switch (scope) {
			case 'openid':
                user_info_out(['sub']);
				break;
			case 'profile':
                user_info_out(['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at']);
				break;
			case 'email':
                user_info_out(['email', 'email_verified']);
				break;
			case 'address':
                user_info_out(['address']);
				break;
			case 'phone':
                user_info_out(['phone_number', 'phone_number_verified']);
                break;
		}
	});

	res.status(200).json(out);
};

app.get('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);
app.post('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);


const server = app.listen(9002, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
