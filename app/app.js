import express from 'express';
import session from 'express-session';
import { Issuer, Strategy } from 'openid-client';
import passport from 'passport';
import vault from 'node-vault';
import ip from 'express-ip';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const userCountryMap = {
  adminuser: 'CA',
  normaluser: 'US',
  otheruser: 'CN'
};

const flagMap = {
  CA: '🇨🇦',
  US: '🇺🇸',
  CN: '🇨🇳',
  Unknown: '🏳️'
};

// Session configuration will be set after environment variables are defined
app.use(ip().getIpInfoMiddleware);
app.use((req, res, next) => {
        if (req.session?.country) {
        req.ipInfo = {
            ip: req.ip,
            country: req.session.country
        };
    }
    next();
});



app.use((req, res, next) => {
    const username = req.user?.preferred_username || 'anonymous';
    const country = req.ipInfo?.country || 'Unknown';
    const flag = flagMap[req.ipInfo?.country] || '🏳️';
    const url = req.originalUrl;
    console.log(`[${new Date().toISOString()}] ${username} from ${country} accessed ${url}`);
    next();
});



// Environment variables with defaults
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'security-demo';
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'demo-client';
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || 'p2TG8mocRTMUYPSLRrPKrwF4fa661AqE';
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3000';
const APP_CALLBACK_URL = process.env.APP_CALLBACK_URL || 'http://localhost:3000/callback';
const VAULT_URL = process.env.VAULT_URL || 'http://127.0.0.1:8200';
const VAULT_TOKEN = process.env.VAULT_TOKEN || 'myroot';
const SESSION_SECRET = process.env.SESSION_SECRET || 'demo';
const SESSION_MAX_AGE = parseInt(process.env.SESSION_MAX_AGE) || 86400000;
const ALLOWED_ROLES = process.env.ALLOWED_ROLES?.split(',') || ['admin', 'user'];

// Configure session
app.use(session({ 
    secret: SESSION_SECRET, 
    resave: false, 
    saveUninitialized: true,
    cookie: {
        maxAge: SESSION_MAX_AGE,
        httpOnly: true,
        secure: NODE_ENV === 'production'
    }
}));

// Configure Passport middleware (must be after session middleware)
app.use(passport.initialize());
app.use(passport.session());

const vaultClient = vault({ endpoint: VAULT_URL, token: VAULT_TOKEN });
const secret = await vaultClient.read('secret/data/demo');
console.log(secret.data.data.password);

const keycloakIssuer = await Issuer.discover(`${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`);
const client = new keycloakIssuer.Client({
    client_id: KEYCLOAK_CLIENT_ID,
    client_secret: KEYCLOAK_CLIENT_SECRET,
    redirect_uris: [APP_CALLBACK_URL],
    response_types: ['code'],
});

passport.use('oidc', new Strategy({ client }, (tokenSet, userinfo, done) => {
    userinfo.tokenSet = tokenSet;
    return done(null, userinfo);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get('/login', passport.authenticate('oidc'));


app.get('/callback',
    passport.authenticate('oidc', {
      failureRedirect: '/login',
    }),
    (req, res) => {
      // store tokenSet in session
      req.session.tokenSet = req.user.tokenSet;
      const username = req.user.preferred_username;
      const country = userCountryMap[username] || 'Unknown';

      req.session.country = country;  // Store in session
      res.redirect('/');
    }
  );


function enforceZeroTrust(req, res, next) {
    const tokenSet = req.session.tokenSet;
    const now = Date.now();

    // 1. Token missing or expired
    if (!tokenSet || !tokenSet.expires_at || tokenSet.expires_at * 1000 < now) {
        req.logout(() => {
            req.session.destroy(() => {
                return res.redirect('/login');
            });
        });
        return;
    }

    // 2. Role check
    // const roles = req.user?.realm_access?.roles || [];
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    console.log("user: "+req.user.preferred_username);
    console.log(roles);
    const allowedRoles = ALLOWED_ROLES;
    const hasAccess = roles.some(role => allowedRoles.includes(role));
    if (!hasAccess) {
         return res.status(403).send(`
        <html>
            <head><title>Access Denied</title></head>
            <body style="font-family:sans-serif; padding:2rem;">
                <h2>403 - Access Denied</h2>
                <p>You do not have sufficient privileges to view this page.</p>
                <a href="/logout">Logout</a>
            </body>
        </html>
    `);
    }

    next();
}

app.get('/logout', (req, res) => {
    const idToken = req.session.tokenSet?.id_token;
    req.logout(() => {
        req.session.destroy(() => {
            const keycloakLogoutUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout?post_logout_redirect_uri=${APP_BASE_URL}&id_token_hint=${idToken}`;
            res.redirect(keycloakLogoutUrl);
        });
    });
});



function requireLogin(req, res, next) {
    if (!req.user) {
        return res.redirect('/login');
    }
    next();
}

app.get('/', async (req, res) => {
    if (!req.user) {
        // not logged in: show login link
        // enforceZeroTrust(req, res, next);
        return res.send(`
            <h1>Welcome to the Demo App</h1>
            <p>Your access country: ${req.ipInfo?.country || 'CA'}</p>
            <p>You are not logged in.</p>
            <a href="/login">Login</a>

             <h2>Example Users</h2>
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse; font-family:sans-serif;">
        <thead>
            <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Roles</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>adminuser</td>
                <td>password</td>
                <td>admin</td>
            </tr>
            <tr>
                <td>normaluser</td>
                <td>password</td>
                <td>user</td>
            </tr>
            <tr>
                <td>otheruser</td>
                <td>password</td>
                <td>no role</td>
            </tr>
        </tbody>
    </table>
        `);
    }

    // already logged in: show user info and secret
    // enforceZeroTrust(req, res, next);
    const tokenSet = req.session.tokenSet;
    const now = Date.now();

    if (!tokenSet || !tokenSet.expires_at || tokenSet.expires_at * 1000 < now) {
        req.logout(() => {
            req.session.destroy(() => {
                return res.redirect('/login');
            });
        });
        return;
    }

    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    const allowedRoles = ALLOWED_ROLES;
    const hasAccess = roles.some(role => allowedRoles.includes(role));

    const isAdmin = roles.includes('admin');
    const isUser = roles.includes('user');

    if (!hasAccess) {
         return res.status(403).send(`
        <html>
            <head><title>Access Denied</title></head>

            <body style="font-family:sans-serif; padding:2rem;">
                <h2>403 - Access Denied</h2>
                <p>Your access country: ${req.ipInfo?.country || 'Unknown'}</p>
                <p>You do not have sufficient privileges to view this page.</p>
                <a href="/logout">Logout</a>
            </body>
        </html>
    `);
    }

    const secret = await vaultClient.read('secret/data/demo');

    res.send(`
        <h1>Hello ${req.user.preferred_username}</h1>
        <p>Your access country: ${req.ipInfo?.country || 'Unknown'}</p>
        <p>Secret: ${secret.data.data.password}</p>
        <ul>
            ${isAdmin ? `<li><a href="/admin">Go to Admin Page</a></li>` : ''}
            ${isAdmin ? `<li><a href="/secrets">View System Secrets</a></li>` : ''}
            ${isUser || isAdmin ? `<li><a href="/user">Go to User Page</a></li>` : ''}
            <li><a href="/logout">Logout</a></li>
        </ul>
    `);
});


app.get('/admin', enforceZeroTrust, (req, res) => {
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    if (!roles.includes('admin')) {
        return res.status(403).send('<h3>403 - Admin Only</h3><a href="/">Home</a>');
    }
    res.send('<h1>Admin Page</h1><p>Only visible to admins.</p><a href="/">Back</a>');
});

app.get('/user', enforceZeroTrust, (req, res) => {
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    if (!(roles.includes('user') || roles.includes('admin'))) {
        return res.status(403).send('<h3>403 - User Access Only</h3><a href="/">Home</a>');
    }
    res.send('<h1>User Page</h1><p>Welcome to the user page.</p><a href="/">Back</a>');
});

app.get('/guest', enforceZeroTrust, (req, res) => {
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    if (roles.length > 0) {
        return res.status(403).send('<h3>403 - Guest Only</h3><a href="/">Home</a>');
    }
    res.send('<h1>Guest Page</h1><p>Only for users without roles.</p><a href="/">Back</a>');
});


app.get('/secrets', enforceZeroTrust, async (req, res) => {
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    if (!roles.includes('admin')) {
        return res.status(403).send('<h3>403 - Only admins can view system secrets</h3><a href="/">Back</a>');
    }

    const username = req.user.preferred_username;

    try {
        const demoSecret = await vaultClient.read('secret/data/demo');
        const userSecret = await vaultClient.read(`secret/data/users/${username}`);
        const configSecret = await vaultClient.read('secret/data/config');
        const flagSecret = await vaultClient.read('secret/data/feature_flags');

        res.send(`
            <h1>🔐 Vault Secrets for ${username}</h1>
            <h2>User Secrets</h2>
            <ul>
                <li>Password: ${userSecret.data.data.password}</li>
                <li>API Key: ${userSecret.data.data.apiKey}</li>
            </ul>

            <h2>System Config</h2>
            <ul>
                <li>SMTP Host: ${configSecret.data.data.smtpHost}</li>
                <li>SMTP Pass: ${configSecret.data.data.smtpPass}</li>
            </ul>

            <h2>Feature Flags</h2>
            <ul>
                <li>Demo Banner: ${flagSecret.data.data.demoBanner}</li>
                <li>Maintenance Mode: ${flagSecret.data.data.maintenanceMode}</li>
            </ul>

            <a href="/">⬅️ Back to Home</a>
        `);
    } catch (err) {
        console.error("Vault Error:", err.message);
        res.status(500).send("Error retrieving secrets from Vault");
    }
});


app.listen(PORT, () => console.log(`Server started at ${APP_BASE_URL}`));