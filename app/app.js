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
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied - Security Demo</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #333;
                }
                .container {
                    background: white;
                    padding: 3rem;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                    width: 90%;
                }
                .error-icon {
                    font-size: 4rem;
                    color: #e74c3c;
                    margin-bottom: 1rem;
                }
                h1 { color: #e74c3c; margin-bottom: 1rem; font-size: 2rem; }
                p { margin-bottom: 2rem; color: #666; line-height: 1.6; }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: #3498db;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                .btn:hover {
                    background: #2980b9;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">🚫</div>
                <h1>403 - Access Denied</h1>
                <p>You do not have sufficient privileges to view this page. Please contact your administrator for access.</p>
                <a href="/logout" class="btn">Logout</a>
            </div>
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
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Demo App - Welcome</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 2rem;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 3rem 2rem;
                    text-align: center;
                }
                .header h1 {
                    font-size: 2.5rem;
                    margin-bottom: 1rem;
                    font-weight: 300;
                }
                .header p {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }
                .content {
                    padding: 3rem 2rem;
                }
                .status-card {
                    background: #f8f9fa;
                    border-radius: 12px;
                    padding: 1.5rem;
                    margin-bottom: 2rem;
                    border-left: 4px solid #3498db;
                }
                .login-section {
                    text-align: center;
                    margin-bottom: 3rem;
                }
                .btn {
                    display: inline-block;
                    padding: 15px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 10px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                    font-size: 1.1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .btn:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 8px 25px rgba(0,0,0,0.3);
                }
                .users-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 1rem;
                    background: white;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                .users-table th {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 1rem;
                    text-align: left;
                    font-weight: 500;
                }
                .users-table td {
                    padding: 1rem;
                    border-bottom: 1px solid #eee;
                }
                .users-table tr:hover {
                    background: #f8f9fa;
                }
                .role-badge {
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 500;
                }
                .role-admin { background: #e74c3c; color: white; }
                .role-user { background: #3498db; color: white; }
                .role-none { background: #95a5a6; color: white; }
                .section-title {
                    font-size: 1.5rem;
                    margin-bottom: 1rem;
                    color: #2c3e50;
                    font-weight: 600;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Security Demo App</h1>
                    <p>Zero Trust Security with Keycloak & Vault Integration</p>
                </div>
                <div class="content">
                    <div class="status-card">
                        <h3>📍 Access Location</h3>
                        <p>Your access country: <strong>${req.ipInfo?.country || 'CA'}</strong></p>
                    </div>
                    
                    <div class="login-section">
                        <h2 class="section-title">🔑 Authentication Required</h2>
                        <p style="margin-bottom: 2rem; color: #666;">Please log in to access the secure features of this application.</p>
                        <a href="/login" class="btn">Login with Keycloak</a>
                    </div>

                    <div>
                        <h2 class="section-title">👥 Test Users</h2>
                        <p style="margin-bottom: 1rem; color: #666;">Use these credentials to test different access levels:</p>
                        <table class="users-table">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Password</th>
                                    <th>Role</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><strong>adminuser</strong></td>
                                    <td>password</td>
                                    <td><span class="role-badge role-admin">Admin</span></td>
                                </tr>
                                <tr>
                                    <td><strong>normaluser</strong></td>
                                    <td>password</td>
                                    <td><span class="role-badge role-user">User</span></td>
                                </tr>
                                <tr>
                                    <td><strong>otheruser</strong></td>
                                    <td>password</td>
                                    <td><span class="role-badge role-none">No Role</span></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </body>
        </html>
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
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dashboard - Security Demo</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 2rem;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 2rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .user-info {
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                }
                .avatar {
                    width: 50px;
                    height: 50px;
                    background: rgba(255,255,255,0.2);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 1.5rem;
                }
                .content {
                    padding: 3rem 2rem;
                }
                .dashboard-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-bottom: 3rem;
                }
                .card {
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 2rem;
                    border-left: 4px solid #3498db;
                    transition: transform 0.3s ease;
                }
                .card:hover {
                    transform: translateY(-5px);
                }
                .card h3 {
                    color: #2c3e50;
                    margin-bottom: 1rem;
                    font-size: 1.3rem;
                }
                .secret-card {
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    color: white;
                    border-left-color: #e74c3c;
                }
                .secret-card h3 {
                    color: white;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                    margin: 0.5rem;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .btn-danger {
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                }
                .btn-success {
                    background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
                }
                .btn-warning {
                    background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
                }
                .navigation {
                    text-align: center;
                    margin-top: 2rem;
                    padding-top: 2rem;
                    border-top: 1px solid #eee;
                }
                .role-badge {
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 500;
                    margin-left: 1rem;
                }
                .role-admin { background: #e74c3c; color: white; }
                .role-user { background: #3498db; color: white; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="user-info">
                        <div class="avatar">👤</div>
                        <div>
                            <h1>Welcome, ${req.user.preferred_username}!</h1>
                            <p>📍 Access from: ${req.ipInfo?.country || 'Unknown'}</p>
                        </div>
                    </div>
                    <div>
                        ${isAdmin ? '<span class="role-badge role-admin">Admin</span>' : ''}
                        ${isUser ? '<span class="role-badge role-user">User</span>' : ''}
                    </div>
                </div>
                <div class="content">
                    <div class="dashboard-grid">
                        <div class="card">
                            <h3>🔐 Vault Secret</h3>
                            <p><strong>Password:</strong> ${secret.data.data.password}</p>
                        </div>
                        <div class="card">
                            <h3>🔑 Authentication Status</h3>
                            <p><strong>Token Expires:</strong> ${new Date(tokenSet.expires_at * 1000).toLocaleString()}</p>
                            <p><strong>Roles:</strong> ${roles.join(', ') || 'None'}</p>
                        </div>
                    </div>
                    
                    <div class="navigation">
                        <h3 style="margin-bottom: 1rem; color: #2c3e50;">Quick Actions</h3>
                        ${isAdmin ? '<a href="/admin" class="btn btn-warning">🔧 Admin Panel</a>' : ''}
                        ${isAdmin ? '<a href="/secrets" class="btn btn-danger">🔐 System Secrets</a>' : ''}
                        ${isUser || isAdmin ? '<a href="/user" class="btn btn-success">👤 User Dashboard</a>' : ''}
                        <a href="/logout" class="btn btn-danger">🚪 Logout</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `);
});


app.get('/admin', enforceZeroTrust, (req, res) => {
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    if (!roles.includes('admin')) {
        return res.status(403).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied - Admin Only</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #333;
                }
                .container {
                    background: white;
                    padding: 3rem;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                    width: 90%;
                }
                .error-icon {
                    font-size: 4rem;
                    color: #e74c3c;
                    margin-bottom: 1rem;
                }
                h1 { color: #e74c3c; margin-bottom: 1rem; font-size: 2rem; }
                p { margin-bottom: 2rem; color: #666; line-height: 1.6; }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: #3498db;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                .btn:hover {
                    background: #2980b9;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">🚫</div>
                <h1>403 - Admin Access Required</h1>
                <p>This page is restricted to administrators only. Please contact your system administrator for access.</p>
                <a href="/" class="btn">Back to Home</a>
            </div>
        </body>
        </html>
        `);
    }
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Panel - Security Demo</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 2rem;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    color: white;
                    padding: 3rem 2rem;
                    text-align: center;
                }
                .header h1 {
                    font-size: 2.5rem;
                    margin-bottom: 1rem;
                    font-weight: 300;
                }
                .header p {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }
                .content {
                    padding: 3rem 2rem;
                }
                .admin-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-bottom: 3rem;
                }
                .card {
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 2rem;
                    border-left: 4px solid #e74c3c;
                    transition: transform 0.3s ease;
                }
                .card:hover {
                    transform: translateY(-5px);
                }
                .card h3 {
                    color: #2c3e50;
                    margin-bottom: 1rem;
                    font-size: 1.3rem;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                    margin: 0.5rem;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .btn-danger {
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                }
                .navigation {
                    text-align: center;
                    margin-top: 2rem;
                    padding-top: 2rem;
                    border-top: 1px solid #eee;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔧 Admin Panel</h1>
                    <p>System Administration & Security Management</p>
                </div>
                <div class="content">
                    <div class="admin-grid">
                        <div class="card">
                            <h3>👥 User Management</h3>
                            <p>Manage user accounts, roles, and permissions across the system.</p>
                        </div>
                        <div class="card">
                            <h3>🔐 Security Settings</h3>
                            <p>Configure authentication policies, access controls, and security parameters.</p>
                        </div>
                        <div class="card">
                            <h3>📊 System Monitoring</h3>
                            <p>Monitor system performance, security events, and user activities.</p>
                        </div>
                        <div class="card">
                            <h3>⚙️ Configuration</h3>
                            <p>Manage system configuration, environment variables, and application settings.</p>
                        </div>
                    </div>
                    
                    <div class="navigation">
                        <a href="/secrets" class="btn btn-danger">🔐 View System Secrets</a>
                        <a href="/" class="btn">🏠 Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `);
});

app.get('/user', enforceZeroTrust, (req, res) => {
    const roles = req.user?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
    if (!(roles.includes('user') || roles.includes('admin'))) {
        return res.status(403).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied - User Only</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #333;
                }
                .container {
                    background: white;
                    padding: 3rem;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                    width: 90%;
                }
                .error-icon {
                    font-size: 4rem;
                    color: #e74c3c;
                    margin-bottom: 1rem;
                }
                h1 { color: #e74c3c; margin-bottom: 1rem; font-size: 2rem; }
                p { margin-bottom: 2rem; color: #666; line-height: 1.6; }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: #3498db;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                .btn:hover {
                    background: #2980b9;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">🚫</div>
                <h1>403 - User Access Required</h1>
                <p>This page requires user-level permissions. Please contact your administrator for access.</p>
                <a href="/" class="btn">Back to Home</a>
            </div>
        </body>
        </html>
        `);
    }
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>User Dashboard - Security Demo</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 2rem;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
                    color: white;
                    padding: 3rem 2rem;
                    text-align: center;
                }
                .header h1 {
                    font-size: 2.5rem;
                    margin-bottom: 1rem;
                    font-weight: 300;
                }
                .header p {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }
                .content {
                    padding: 3rem 2rem;
                }
                .user-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-bottom: 3rem;
                }
                .card {
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 2rem;
                    border-left: 4px solid #3498db;
                    transition: transform 0.3s ease;
                }
                .card:hover {
                    transform: translateY(-5px);
                }
                .card h3 {
                    color: #2c3e50;
                    margin-bottom: 1rem;
                    font-size: 1.3rem;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                    margin: 0.5rem;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .btn-success {
                    background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
                }
                .navigation {
                    text-align: center;
                    margin-top: 2rem;
                    padding-top: 2rem;
                    border-top: 1px solid #eee;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>👤 User Dashboard</h1>
                    <p>Welcome to your personalized user workspace</p>
                </div>
                <div class="content">
                    <div class="user-grid">
                        <div class="card">
                            <h3>📋 My Profile</h3>
                            <p>View and manage your personal information and account settings.</p>
                        </div>
                        <div class="card">
                            <h3>📁 My Files</h3>
                            <p>Access and manage your personal files and documents.</p>
                        </div>
                        <div class="card">
                            <h3>🔔 Notifications</h3>
                            <p>Check your system notifications and important updates.</p>
                        </div>
                        <div class="card">
                            <h3>⚙️ Preferences</h3>
                            <p>Customize your application preferences and settings.</p>
                        </div>
                    </div>
                    
                    <div class="navigation">
                        <a href="/" class="btn btn-success">🏠 Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `);
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
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>System Secrets - Security Demo</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 2rem;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    color: white;
                    padding: 3rem 2rem;
                    text-align: center;
                }
                .header h1 {
                    font-size: 2.5rem;
                    margin-bottom: 1rem;
                    font-weight: 300;
                }
                .header p {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }
                .content {
                    padding: 3rem 2rem;
                }
                .secrets-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                    gap: 2rem;
                    margin-bottom: 3rem;
                }
                .secret-card {
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 2rem;
                    border-left: 4px solid #e74c3c;
                    transition: transform 0.3s ease;
                }
                .secret-card:hover {
                    transform: translateY(-5px);
                }
                .secret-card h3 {
                    color: #2c3e50;
                    margin-bottom: 1.5rem;
                    font-size: 1.3rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                .secret-item {
                    background: white;
                    padding: 1rem;
                    border-radius: 8px;
                    margin-bottom: 1rem;
                    border: 1px solid #e9ecef;
                }
                .secret-label {
                    font-weight: 600;
                    color: #495057;
                    margin-bottom: 0.5rem;
                    font-size: 0.9rem;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                .secret-value {
                    font-family: 'Courier New', monospace;
                    background: #f8f9fa;
                    padding: 0.5rem;
                    border-radius: 4px;
                    color: #e74c3c;
                    font-weight: 500;
                    word-break: break-all;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                    margin: 0.5rem;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .navigation {
                    text-align: center;
                    margin-top: 2rem;
                    padding-top: 2rem;
                    border-top: 1px solid #eee;
                }
                .warning {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    color: #856404;
                    padding: 1rem;
                    border-radius: 8px;
                    margin-bottom: 2rem;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 System Secrets</h1>
                    <p>Vault Integration - Secure Secret Management</p>
                </div>
                <div class="content">
                    <div class="warning">
                        ⚠️ <strong>Security Notice:</strong> This page displays sensitive system information. Access is restricted to administrators only.
                    </div>
                    
                    <div class="secrets-grid">
                        <div class="secret-card">
                            <h3>👤 User Secrets</h3>
                            <div class="secret-item">
                                <div class="secret-label">Password</div>
                                <div class="secret-value">${userSecret.data.data.password}</div>
                            </div>
                            <div class="secret-item">
                                <div class="secret-label">API Key</div>
                                <div class="secret-value">${userSecret.data.data.apiKey}</div>
                            </div>
                        </div>

                        <div class="secret-card">
                            <h3>⚙️ System Configuration</h3>
                            <div class="secret-item">
                                <div class="secret-label">SMTP Host</div>
                                <div class="secret-value">${configSecret.data.data.smtpHost}</div>
                            </div>
                            <div class="secret-item">
                                <div class="secret-label">SMTP Password</div>
                                <div class="secret-value">${configSecret.data.data.smtpPass}</div>
                            </div>
                        </div>

                        <div class="secret-card">
                            <h3>🚩 Feature Flags</h3>
                            <div class="secret-item">
                                <div class="secret-label">Demo Banner</div>
                                <div class="secret-value">${flagSecret.data.data.demoBanner}</div>
                            </div>
                            <div class="secret-item">
                                <div class="secret-label">Maintenance Mode</div>
                                <div class="secret-value">${flagSecret.data.data.maintenanceMode}</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="navigation">
                        <a href="/admin" class="btn">🔧 Admin Panel</a>
                        <a href="/" class="btn">🏠 Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        `);
    } catch (err) {
        console.error("Vault Error:", err.message);
        res.status(500).send("Error retrieving secrets from Vault");
    }
});


app.listen(PORT, () => console.log(`Server started at ${APP_BASE_URL}`));