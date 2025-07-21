import express from 'express';
import session from 'express-session';
import { Issuer, Strategy } from 'openid-client';
import passport from 'passport';
import ip from 'express-ip';
import authService from './services/authService.js';
import PageRoutes from './routes/pageRoutes.js';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();

// IP middleware setup
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

// Logging middleware
app.use((req, res, next) => {
    authService.logUserAccess(req);
    next();
});

// 静态资源目录，必须放在所有路由和中间件之前
app.use('/static', express.static(path.join(__dirname, 'views')));

// Environment variables with defaults
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'security-demo';
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'demo-client';
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET;
if (!KEYCLOAK_CLIENT_SECRET) {
    throw new Error('KEYCLOAK_CLIENT_SECRET environment variable is required but not set.');
}
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3000';
const APP_CALLBACK_URL = process.env.APP_CALLBACK_URL || 'http://localhost:3000/callback';
const VAULT_URL = process.env.VAULT_URL || 'http://127.0.0.1:8200';
const VAULT_TOKEN = process.env.VAULT_TOKEN || 'myroot';
const SESSION_SECRET = process.env.SESSION_SECRET || 'demo';
const SESSION_MAX_AGE = parseInt(process.env.SESSION_MAX_AGE) || 86400000;
const ALLOWED_ROLES = process.env.ALLOWED_ROLES?.split(',') || ['admin', 'user'];

// Configuration object
const config = {
    PORT,
    NODE_ENV,
    KEYCLOAK_URL,
    KEYCLOAK_REALM,
    KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET,
    APP_BASE_URL,
    APP_CALLBACK_URL,
    VAULT_URL,
    VAULT_TOKEN,
    SESSION_SECRET,
    SESSION_MAX_AGE,
    ALLOWED_ROLES
};

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

// Initialize Keycloak OIDC
async function initializeKeycloak() {
    try {
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

        // Setup authentication routes
        app.get('/login', passport.authenticate('oidc'));

        app.get('/callback',
            passport.authenticate('oidc', {
                failureRedirect: '/login',
            }),
            async (req, res) => {
                // Store tokenSet in session
                console.log('already logged in: req.user', req.user);
                req.session.tokenSet = req.user.tokenSet;
                const username = req.user.preferred_username;
                const region = req.user.region || 'Unknown';
                const roles = req.user.resource_access.demo-client.roles;
                let vaultRole = 'default';

                if (roles.includes('admin')) {
                    vaultRole = 'admin';
                } else if (roles.includes('user')) {
                    vaultRole = 'user';
                }

                req.session.country = region;  // Store in session
                req.session.username = username;
                const jwt = req.user.tokenSet.id_token || req.user.tokenSet.access_token;




                const vaultResponse = await fetch(`${process.env.VAULT_URL}/v1/auth/oidc/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        role: vaultRole,
                        jwt: jwt,
                    }),
                });
                const result = await vaultResponse.json();

                if (!vaultResponse.ok) {
                    console.error('Vault login failed:', result);
                    return res.status(500).send('Vault login failed');
                }
                req.session.vaultToken = result.auth.client_token;
                console.log('Vault login successful:', result);
                
                res.redirect('/dashboard');
            }
        );

        console.log('Keycloak OIDC initialized successfully');
    } catch (error) {
        console.error('Failed to initialize Keycloak:', error);
        process.exit(1);
    }
}

// User country mapping (for demo purposes)
const userCountryMap = {
    'adminuser': 'CA',
    'normaluser': 'US',
    'otheruser': 'CN'
};

// Initialize page routes
const pageRoutes = new PageRoutes(config);
pageRoutes.setupRoutes(app);

// Initialize the application
async function startApp() {
    await initializeKeycloak();
    
    app.listen(PORT, () => {
        console.log(`🚀 Server started at ${APP_BASE_URL}`);
        console.log(`📊 Environment: ${NODE_ENV}`);
        console.log(`🔐 Keycloak URL: ${KEYCLOAK_URL}`);
        console.log(`🗄️ Vault URL: ${VAULT_URL}`);
    });
}

// Start the application
startApp().catch(error => {
    console.error('Failed to start application:', error);
    process.exit(1);
});