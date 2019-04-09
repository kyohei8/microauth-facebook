const querystring = require('querystring');
const url = require('url');
const cookie = require('cookie');

const rp = require('request-promise');
const redirect = require('micro-redirect');
const uuid = require('uuid');

const provider = 'facebook';
const fb_auth_state = 'R8VTm6asnf';

function parseCookies(request) {
  var list = {},
    rc = request.headers.cookie;

  rc &&
    rc.split(';').forEach(function (cookie) {
      var parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });

  return list;
}

function genCookies(key, val) {
  // 1hour
  const expiresIn = 60 * 60 * 1000;
  const options = {
    maxAge: expiresIn,
    httpOnly: true
  };
  return cookie.serialize(key, val, options);
}

function deleteCookies(key) {
  const expiresIn = 0;
  const options = {
    maxAge: expiresIn,
    httpOnly: true
  };
  return cookie.serialize(key, '**', options);
}

const microAuthFacebook = ({ appId, appSecret, fields = 'name,email,cover', callbackUrl, path = '/auth/facebook', scope = 'public_profile,email', apiVersion = '2.11' }) => {

  const getRedirectUrl = state => {
    return `https://www.facebook.com/dialog/oauth?client_id=${appId}&redirect_uri=${callbackUrl}&response_type=code&state=${state}&scope=${scope}`;
  };

  const getAccessTokenUrl = code => {
    return `https://graph.facebook.com/v${apiVersion}/oauth/access_token?client_id=${appId}&redirect_uri=${callbackUrl}&client_secret=${appSecret}&code=${code}`;
  };

  const getUserInfoUrl = accessToken => {
    return `https://graph.facebook.com/v${apiVersion}/me?access_token=${accessToken}&fields=${fields}`;
  };

  const states = [];
  return fn => async (req, res, ...args) => {

    const { pathname, query } = url.parse(req.url);

    if (pathname === path) {
      try {
        const state = uuid.v4();
        const redirectUrl = getRedirectUrl(state);
        states.push(state);
        const cookie = genCookies(fb_auth_state, states.join(','))
        res.setHeader('Set-Cookie', cookie);
        return redirect(res, 302, redirectUrl);
      } catch (err) {
        args.push({ err, provider });
        return fn(req, res, ...args);
      }

    }

    const callbackPath = url.parse(callbackUrl).pathname;
    if (pathname === callbackPath) {
      try {
        const { state, code } = querystring.parse(query);

        const cookies = parseCookies(req);
        // delete cookie
        const delCookie = deleteCookies(fb_auth_state);
        res.setHeader('Set-Cookie', delCookie);

        if (!states.includes(state)) {
          console.log('states', cookies[fb_auth_state], state);
          // get state by cookies
          const states = cookies[fb_auth_state];
          console.log('has states', states.split('%2C').includes(state));
          if (!states.split('%2C').includes(state)) {
            const err = new Error('Invalid state');
            args.push({ err, provider });
            return fn(req, res, ...args);
          }
        }

        const response = await rp({
          method: 'GET',
          url: getAccessTokenUrl(code),
          json: true
        });

        const accessToken = response.access_token;
        const info = await rp({
          method: 'GET',
          url: getUserInfoUrl(accessToken),
          json: true
        });

        const result = {
          provider,
          accessToken,
          info
        };

        args.push({ result });
        return fn(req, res, ...args);
      } catch (err) {
        args.push({ err, provider });
        return fn(req, res, ...args);
      }
    }

    return fn(req, res, ...args);
  };
};

module.exports = microAuthFacebook;
