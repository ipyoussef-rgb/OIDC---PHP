<?php
// src/config.php

define('OIDC_PROVIDER_URL', getenv('https://idp.mycityapp.cloud.test.kobil.com/auth/realms/worms/.well-known/openid-configuration'));    // e.g. https://your-idp/.well-known/openid-configuration
define('OIDC_CLIENT_ID', getenv('OIDC_CLIENT_ID'));
define('OIDC_CLIENT_SECRET', getenv('OIDC_CLIENT_SECRET'));
define('OIDC_REDIRECT_URI', getenv('OIDC_REDIRECT_URI'));    // must match Vercel URL
define('OIDC_LOGOUT_REDIRECT', getenv('OIDC_LOGOUT_REDIRECT') ?: '/');
define('OIDC_SCOPES', ['openid', 'profile', 'email']);
