import templateEngine from '../views/templateEngine.js';

class PageController {
    // Render welcome page for non-logged in users
    renderWelcome(req, res) {
        const data = {
            country: req.ipInfo?.country || 'CA'
        };
        
        const html = templateEngine.render('welcome', data);
        res.send(html);
    }

    // Render dashboard for logged in users
    renderDashboard(req, res, secret) {
        const roles = req.user?.resource_access?.[req.app.locals.KEYCLOAK_CLIENT_ID]?.roles || [];
        const isAdmin = roles.includes('admin');
        const isUser = roles.includes('user');
        
        // Generate role badges
        let roleBadges = '';
        if (isAdmin) roleBadges += '<span class="role-badge role-admin">Admin</span>';
        if (isUser) roleBadges += '<span class="role-badge role-user">User</span>';
        
        // Generate admin buttons
        let adminButtons = '';
        if (isAdmin) {
            adminButtons += '<a href="/admin" class="btn btn-warning">🔧 Admin Panel</a>';
            adminButtons += '<a href="/secrets" class="btn btn-danger">🔐 System Secrets</a>';
        }
        
        // Generate user buttons
        let userButtons = '';
        if (isUser || isAdmin) {
            userButtons += '<a href="/user" class="btn btn-success">👤 User Dashboard</a>';
        }

        const data = {
            username: req.user.preferred_username,
            country: req.ipInfo?.country || 'Unknown',
            roleBadges: roleBadges,
            secret: secret.data.data.password,
            tokenExpires: new Date(req.session.tokenSet.expires_at * 1000).toLocaleString(),
            roles: roles.join(', ') || 'None',
            adminButtons: adminButtons,
            userButtons: userButtons
        };
        
        const html = templateEngine.render('dashboard', data);
        res.send(html);
    }

    // Render admin panel
    renderAdmin(req, res) {
        const html = templateEngine.render('admin');
        res.send(html);
    }

    // Render user dashboard
    renderUser(req, res) {
        const html = templateEngine.render('user');
        res.send(html);
    }

    // Render system secrets
    renderSecrets(req, res, secrets) {
        const data = {
            userPassword: secrets.userSecret.data.data.password,
            userApiKey: secrets.userSecret.data.data.apiKey,
            smtpHost: secrets.configSecret.data.data.smtpHost,
            smtpPass: secrets.configSecret.data.data.smtpPass,
            demoBanner: secrets.flagSecret.data.data.demoBanner,
            maintenanceMode: secrets.flagSecret.data.data.maintenanceMode
        };
        
        const html = templateEngine.render('secrets', data);
        res.send(html);
    }

    // Render access denied error
    renderAccessDenied(req, res, message = 'You do not have sufficient privileges to view this page.') {
        const html = templateEngine.renderError(message, '403 - Access Denied');
        res.status(403).send(html);
    }

    // Render admin access denied
    renderAdminAccessDenied(req, res) {
        const message = 'This page is restricted to administrators only. Please contact your system administrator for access.';
        const html = templateEngine.renderError(message, '403 - Admin Access Required');
        res.status(403).send(html);
    }

    // Render user access denied
    renderUserAccessDenied(req, res) {
        const message = 'This page requires user-level permissions. Please contact your administrator for access.';
        const html = templateEngine.renderError(message, '403 - User Access Required');
        res.status(403).send(html);
    }
}

export default new PageController(); 