#!/bin/bash

# set vault address and token
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_TOKEN=${VAULT_TOKEN:-myroot}

echo "🔐 Enabling KV v2 at secret/"
vault secrets enable -path=secret -version=2 kv || echo "KV already enabled"

echo "📌 Writing test secret data..."
vault kv put secret/demo password="demo123" api_key="abcd-1234"

vault kv put secret/users/adminuser email="admin@example.com" role="admin" region="CA"
vault kv put secret/users/normaluser email="user@example.com" role="user" region="US"

vault kv put secret/config system_name="SecureApp" version="1.0.0" maintenance_mode="false"

vault kv put secret/feature_flags beta_feature=true dark_mode=true ai_assistant=false

echo "🛡️ Creating policies..."

cat <<EOF | vault policy write canada -
path "secret/data/*" {
  capabilities = ["read"]
}
EOF

cat <<EOF | vault policy write us -
path "secret/data/demo" {
  capabilities = ["read"]
}
path "secret/data/users/normaluser" {
  capabilities = ["read"]
}
EOF

echo "🔐 Creating OIDC roles..."

vault write auth/oidc/role/ca-role \
  bound_audiences="vault" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  user_claim="preferred_username" \
  bound_claims.region="CA" \
  policies="canada" \
  ttl="1h"

vault write auth/oidc/role/us-role \
  bound_audiences="vault" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  user_claim="preferred_username" \
  bound_claims.region="US" \
  policies="us" \
  ttl="1h"

echo "✅ Initialization complete!"