class AuthService {
    constructor() {
        this.flagMap = {
            CA: '🇨🇦',
            US: '🇺🇸',
            CN: '🇨🇳',
            Unknown: '🏳️'
        };
    }

    // Check if user has required roles
    hasRequiredRoles(user, clientId, allowedRoles) {
        const roles = user?.resource_access?.[clientId]?.roles || [];
        return roles.some(role => allowedRoles.includes(role));
    }

    // Check if user is admin
    isAdmin(user, clientId) {
        const roles = user?.resource_access?.[clientId]?.roles || [];
        return roles.includes('admin');
    }

    // Check if user has user role
    isUser(user, clientId) {
        const roles = user?.resource_access?.[clientId]?.roles || [];
        return roles.includes('user');
    }

    // Validate token expiration
    isTokenValid(tokenSet) {
        if (!tokenSet || !tokenSet.expires_at) {
            return false;
        }
        const now = Date.now();
        return tokenSet.expires_at * 1000 > now;
    }

    // Get user roles
    getUserRoles(user, clientId) {
        return user?.resource_access?.[clientId]?.roles || [];
    }

    // Get country flag
    getCountryFlag(country) {
        return this.flagMap[country] || this.flagMap.Unknown;
    }

    // Log user access
    logUserAccess(req) {
        const username = req.user?.preferred_username || 'anonymous';
        const country = req.ipInfo?.country || 'Unknown';
        const flag = this.getCountryFlag(country);
        const url = req.originalUrl;
        console.log(`[${new Date().toISOString()}] ${username} from ${country} ${flag} accessed ${url}`);
    }
}

export default new AuthService(); 