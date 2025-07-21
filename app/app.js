import express from 'express';
import session from 'express-session';
import { Issuer, Strategy } from 'openid-client';
import passport from 'passport';
import ip from 'express-ip';
import authService from './services/authService.js';
import PageRoutes from './routes/pageRoutes.js';

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
            (req, res) => {
                // Store tokenSet in session
                req.session.tokenSet = req.user.tokenSet;
                const username = req.user.preferred_username;
                const country = userCountryMap[username] || 'Unknown';

                req.session.country = country;  // Store in session
                res.redirect('/');
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