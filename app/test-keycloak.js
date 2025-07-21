import { Issuer } from 'openid-client';

async function testKeycloakConnection() {
    try {
        console.log('Testing Keycloak connection...');
        
        const keycloakIssuer = await Issuer.discover('http://localhost:8080/realms/security-demo');
        console.log('✅ Keycloak discovery successful');
        console.log('Issuer URL:', keycloakIssuer.metadata.issuer);
        console.log('Authorization endpoint:', keycloakIssuer.metadata.authorization_endpoint);
        console.log('Token endpoint:', keycloakIssuer.metadata.token_endpoint);
        
        const client = new keycloakIssuer.Client({
            client_id: 'demo-client',
            client_secret: '6LNRUk2GJdWm6rjYuoBQ5MUnFT5tyTX6',
            redirect_uris: ['http://localhost:3000/callback'],
            response_types: ['code'],
        });
        
        console.log('✅ Client configuration successful');
        console.log('Client ID:', client.client_id);
        console.log('Redirect URIs:', client.redirect_uris);
        
        // test authorization URL generation
        const authUrl = client.authorizationUrl({
            scope: 'openid profile email',
            state: 'test-state'
        });
        console.log('✅ Authorization URL generated successfully');
        console.log('Auth URL:', authUrl);
        
    } catch (error) {
        console.error('❌ Keycloak connection failed:', error.message);
        console.error('Full error:', error);
    }
}

testKeycloakConnection(); 