import vault from 'node-vault';

class VaultService {
    constructor(vaultUrl, vaultToken) {
        this.client = vault({ endpoint: vaultUrl, token: vaultToken });
    }

    // Get demo secret
    async getDemoSecret() {
        try {
            return await this.client.read('secret/data/demo');
        } catch (error) {
            console.error('Error reading demo secret:', error.message);
            throw error;
        }
    }

    // Get user secrets
    async getUserSecrets(username) {
        try {
            return await this.client.read(`secret/data/users/${username}`);
        } catch (error) {
            console.error(`Error reading user secrets for ${username}:`, error.message);
            throw error;
        }
    }

    // Get system configuration
    async getSystemConfig() {
        try {
            return await this.client.read('secret/data/config');
        } catch (error) {
            console.error('Error reading system config:', error.message);
            throw error;
        }
    }

    // Get feature flags
    async getFeatureFlags() {
        try {
            return await this.client.read('secret/data/feature_flags');
        } catch (error) {
            console.error('Error reading feature flags:', error.message);
            throw error;
        }
    }

    // Get all secrets for admin view
    async getAllSecrets(username) {
        try {
            const [userSecret, configSecret, flagSecret] = await Promise.all([
                this.getUserSecrets(username),
                this.getSystemConfig(),
                this.getFeatureFlags()
            ]);

            return {
                userSecret,
                configSecret,
                flagSecret
            };
        } catch (error) {
            console.error('Error reading all secrets:', error.message);
            throw error;
        }
    }
}

export default VaultService; 