// @flow
import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { capitalize } from "lodash";
import { Strategy as Auth0Strategy } from "passport-auth0";
import accountProvisioner from "../../commands/accountProvisioner";
import env from "../../env";
import { Auth0InvalidError } from "../../errors.js";
import passportMiddleware from "../../middlewares/passport";
import { getAllowedDomains } from "../../utils/authentication";
import { StateStore } from "../../utils/passport";

const router = new Router();
const providerName = "auth0";
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const allowedDomains = getAllowedDomains();

const scopes = ["openid", "email", "profile"];

export const config = {
  name: "Auth0",
  enabled: !!AUTH0_CLIENT_ID,
};

if (AUTH0_CLIENT_ID) {
  passport.use(
    new Auth0Strategy(
      {
        clientID: AUTH0_CLIENT_ID,
        clientSecret: AUTH0_CLIENT_SECRET,
        domain: AUTH0_DOMAIN,
        callbackURL: `${env.URL}/auth/auth0.callback`,
        passReqToCallback: true,
        store: new StateStore(),
        scope: scopes.join(" "),
        state: false,
      },
      async function (req, accessToken, refreshToken, profile, done) {
        try {
          const email = profile._json.email;
          const domain = email.split("@")[1];
          const subdomain = domain.split(".")[0];
          const teamName = capitalize(subdomain);

          if (allowedDomains && !allowedDomains.includes(domain)) {
            throw new Auth0InvalidError();
          }

          const result = await accountProvisioner({
            ip: req.ip,
            team: {
              name: teamName,
              domain,
              subdomain,
            },
            user: {
              name: profile.displayName,
              email,
              avatarUrl: profile.picture,
            },
            authenticationProvider: {
              name: providerName,
              providerId: domain,
            },
            authentication: {
              providerId: profile.id,
              accessToken,
              refreshToken,
              scopes,
            },
          });
          return done(null, result.user, result);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  router.get("auth0", passport.authenticate(providerName));
  router.get("auth0.callback", passportMiddleware(providerName));
}

export default router;

