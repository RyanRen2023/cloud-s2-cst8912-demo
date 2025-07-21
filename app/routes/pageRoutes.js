import pageController from '../controllers/pageController.js';
import authService from '../services/authService.js';
import VaultService from '../services/vaultService.js';

class PageRoutes {
    constructor(config) {
        this.config = config;
        this.vaultService = new VaultService(config.VAULT_URL, config.VAULT_TOKEN);
    }

    // Middleware to enforce zero trust
    enforceZeroTrust(req, res, next) {
        const tokenSet = req.session.tokenSet;
        
        // Check token validity
        if (!authService.isTokenValid(tokenSet)) {
            req.logout(() => {
                req.session.destroy(() => {
                    return res.redirect('/login');
                });
            });
            return;
        }

        // Check role access
        const roles = authService.getUserRoles(req.user, this.config.APP_CLIENT_ID);
        const hasAccess = authService.hasRequiredRoles(req.user, this.config.APP_CLIENT_ID, this.config.ALLOWED_ROLES);
        
        if (!hasAccess) {
            return pageController.renderAccessDenied(req, res);
        }

        next();
    }

    // Welcome page route
    welcome(req, res) {
        pageController.renderWelcome(req, res);
    }

    // Dashboard route
    async dashboard(req, res) {
        try {
            // Check if user is logged in
            if (!req.user) {
                return pageController.renderWelcome(req, res);
            }

            // Check token validity
            const tokenSet = req.session.tokenSet;
            if (!authService.isTokenValid(tokenSet)) {
                req.logout(() => {
                    req.session.destroy(() => {
                        return res.redirect('/login');
                    });
                });
                return;
            }

            // Check role access
            const hasAccess = authService.hasRequiredRoles(req.user, this.config.APP_CLIENT_ID, this.config.ALLOWED_ROLES);
            if (!hasAccess) {
                return pageController.renderAccessDenied(req, res);
            }

            // Get vault secret
            const secret = await this.vaultService.getDemoSecret();
            
            // Render dashboard
            pageController.renderDashboard(req, res, secret);
        } catch (error) {
            console.error('Dashboard error:', error);
            res.status(500).send('Internal server error');
        }
    }

    // Admin panel route
    admin(req, res) {
        const isAdmin = authService.isAdmin(req.user, this.config.APP_CLIENT_ID);
        
        if (!isAdmin) {
            return pageController.renderAdminAccessDenied(req, res);
        }

        pageController.renderAdmin(req, res);
    }

    // User dashboard route
    user(req, res) {
        const isUser = authService.isUser(req.user, this.config.APP_CLIENT_ID);
        const isAdmin = authService.isAdmin(req.user, this.config.APP_CLIENT_ID);
        
        if (!isUser && !isAdmin) {
            return pageController.renderUserAccessDenied(req, res);
        }

        pageController.renderUser(req, res);
    }

    // System secrets route
    async secrets(req, res) {
        try {
            const isAdmin = authService.isAdmin(req.user, this.config.APP_CLIENT_ID);
            
            if (!isAdmin) {
                return pageController.renderAdminAccessDenied(req, res);
            }

            const username = req.user.preferred_username;
            const secrets = await this.vaultService.getAllSecrets(username);
            
            pageController.renderSecrets(req, res, secrets);
        } catch (error) {
            console.error('Secrets error:', error);
            res.status(500).send('Error retrieving secrets from Vault');
        }
    }

    // Logout route
    logout(req, res) {
        const idToken = req.session.tokenSet?.id_token;
        req.logout(() => {
            req.session.destroy(() => {
                const keycloakLogoutUrl = `${this.config.KEYCLOAK_URL}/realms/${this.config.KEYCLOAK_REALM}/protocol/openid-connect/logout?post_logout_redirect_uri=${this.config.APP_BASE_URL}&id_token_hint=${idToken}`;
                res.redirect(keycloakLogoutUrl);
            });
        });
    }

    // Setup routes
    setupRoutes(app) {
        // Store config in app locals for access in controllers
        app.locals.APP_CLIENT_ID = this.config.APP_CLIENT_ID;
        
        // Page routes
        app.get('/', this.welcome.bind(this));
        app.get('/dashboard', this.dashboard.bind(this));
        app.get('/admin', this.enforceZeroTrust.bind(this), this.admin.bind(this));
        app.get('/user', this.enforceZeroTrust.bind(this), this.user.bind(this));
        app.get('/secrets', this.enforceZeroTrust.bind(this), this.secrets.bind(this));
        app.get('/logout', this.logout.bind(this));
    }
}

export default PageRoutes; 