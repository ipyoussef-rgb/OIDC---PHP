<?php
declare(strict_types=1);

/**
 * Behavior:
 * - OIDC login (Keycloak)
 * - Clicking "Send as PDF" does nothing except POST multipart/form-data to:
 *     {issuer-base}/mpower/v1/users/{USER_ID}/media
 *   with fields: attachment (tiny placeholder) and message (optional)
 */

require __DIR__ . '/../vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;

/** ---------- Load .env (locally); on Vercel use env vars ---------- */
if (class_exists(\Dotenv\Dotenv::class)) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->safeLoad();
}

/** ---------- env() helper ---------- */
function env(string $key, $default = null) {
    if (array_key_exists($key, $_ENV))    return $_ENV[$key];
    if (array_key_exists($key, $_SERVER)) return $_SERVER[$key];
    $v = getenv($key);
    return ($v !== false && $v !== null) ? $v : $default;
}

/** ---------- Sessions (file sessions fine on XAMPP) ---------- */
session_start();

/** ---------- Config ---------- */
$providerUrl    = env('OIDC_PROVIDER_URL');                 // https://host/realms/<realm>  OR  https://host/auth/realms/<realm>
$clientId       = env('OIDC_CLIENT_ID');
$clientSecret   = env('OIDC_CLIENT_SECRET');                // empty if public client
$redirectUri    = env('OIDC_REDIRECT_URI', 'http://localhost/oidc-php/');
$logoutRedirect = env('OIDC_LOGOUT_REDIRECT', '/');

$forceUserId    = env('USER_ID');                           // optional override for {USER_ID}
$curlVerifyPeer = env('CURL_VERIFY_PEER', '1') === '1';
$curlVerifyHost = env('CURL_VERIFY_HOST', '1') === '1';

if (!$providerUrl || !$clientId) {
    http_response_code(500);
    echo "<h2>Configuration error</h2><pre>Missing OIDC_PROVIDER_URL or OIDC_CLIENT_ID.</pre>";
    exit;
}

/** ---------- CSRF helpers ---------- */
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
function csrf_input(): string {
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8') . '">';
}
function check_csrf(): void {
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'])) {
        http_response_code(400); exit('Bad Request (CSRF)');
    }
}

/** ---------- Logout ---------- */
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'] ?? '/', $p['domain'] ?? '', (bool)$p['secure'], (bool)$p['httponly']);
    }
    session_destroy();
    header('Location: ' . $logoutRedirect);
    exit;
}

/** ---------- OIDC authenticate ---------- */
try {
    $oidc = new OpenIDConnectClient($providerUrl, $clientId, $clientSecret);
    $oidc->setRedirectURL($redirectUri);

    // Keep scopes minimal; ensure client has these scopes assigned in Keycloak
    $oidc->addScope(['openid', 'profile', 'email', 'roles']); // if you also want email/profile: 'openid profile email'

    // If discovery is restricted, uncomment to pin endpoints (Keycloak standard):
    // $kcBase = rtrim($providerUrl, '/');
    // $oidc->setAuthorizationEndpoint($kcBase . '/protocol/openid-connect/auth');
    // $oidc->setTokenEndpoint($kcBase . '/protocol/openid-connect/token');
    // $oidc->setUserInfoEndpoint($kcBase . '/protocol/openid-connect/userinfo');
    // $oidc->setEndSessionEndpoint($kcBase . '/protocol/openid-connect/logout');
    // $oidc->setJwksUri($kcBase . '/protocol/openid-connect/certs');

    $oidc->authenticate();

    $accessToken   = $oidc->getAccessToken();
    $idTokenClaims = $oidc->getVerifiedClaims();
    $userinfo      = $oidc->requestUserInfo();
    $claims        = array_merge((array)$idTokenClaims, (array)$userinfo);

    $subject    = $claims['sub'] ?? null; // default USER_ID

} catch (\Throwable $e) {
    http_response_code(500);
    echo "<h2>Login error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
    exit;
}

/** ---------- Helpers ---------- */
function build_media_api_url(string $providerUrl, string $userId): string {
    $u = parse_url($providerUrl);
    if (!$u || empty($u['scheme']) || empty($u['host'])) {
        throw new RuntimeException("Invalid OIDC_PROVIDER_URL for deriving API URL.");
    }
    $scheme = $u['scheme'];
    $host   = $u['host'];
    $port   = isset($u['port']) ? ':' . $u['port'] : '';
    $path   = rtrim($u['path'] ?? '', '/');

    if (str_contains($path, '/.well-known/')) {
        $path = preg_replace('#/\.well-known/.*$#', '', $path);
    }
    if (!preg_match('#/(?:auth/)?realms/[^/]+$#', $path)) {
        throw new RuntimeException("Cannot derive realm from OIDC_PROVIDER_URL path: $path");
    }
    $base = $scheme . '://' . $host . $port . $path;
    return $base . '/mpower/v1/users/' . rawurlencode($userId) . '/media';
}

/**
 * POST multipart/form-data with:
 *  - attachment: tiny placeholder file (1 byte)
 *  - message: optional text (can be empty)
 */
function post_trigger_to_media_api(string $url, string $accessToken, string $message = '', bool $verifyPeer = true, bool $verifyHost = true): array {
    // Create a 1-byte temp file so "attachment" exists (API requires it)
    $tmp = tmpfile();
    $tmpPath = stream_get_meta_data($tmp)['uri'];
    file_put_contents($tmpPath, "0"); // 1 byte

    $cfile = new CURLFile($tmpPath, 'application/octet-stream', 'placeholder.bin');

    $ch = curl_init($url);
    $headers = [
        'Accept: application/json',
        'Authorization: Bearer ' . $accessToken,
        // Do NOT set Content-Type manually; cURL will set proper multipart boundary.
    ];
    $postFields = [
        'attachment' => $cfile,
        'message'    => $message, // may be empty
    ];

    curl_setopt_array($ch, [
        CURLOPT_POST            => true,
        CURLOPT_POSTFIELDS      => $postFields,
        CURLOPT_HTTPHEADER      => $headers,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_HEADER          => true,
        CURLOPT_SSL_VERIFYPEER  => $verifyPeer,
        CURLOPT_SSL_VERIFYHOST  => $verifyHost ? 2 : 0,
        CURLOPT_TIMEOUT         => 30,
    ]);

    $resp = curl_exec($ch);
    if ($resp === false) {
        $err = curl_error($ch);
        curl_close($ch);
        fclose($tmp);
        throw new RuntimeException("cURL error: $err");
    }

    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $rawHeaders = substr($resp, 0, $headerSize);
    $body = substr($resp, $headerSize);

    curl_close($ch);
    fclose($tmp);

    return ['status' => $status, 'headers' => $rawHeaders, 'body' => $body];
}

/** ---------- Handle POST: only trigger API ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();

    if (isset($_POST['send_pdf'])) {
        $userId = $forceUserId ?: ($subject ?? null);
        if (!$userId) {
            http_response_code(500);
            echo "<h2>Cannot determine USER_ID</h2><p>No USER_ID env and no 'sub' claim in token.</p>";
            exit;
        }

        try {
            $mediaUrl = build_media_api_url($providerUrl, $userId);

            // Optional message (blank by default)
            $message = isset($_POST['message']) ? (string)$_POST['message'] : '';

            // DEBUG: show the exact URL being called
            echo "<p>DEBUG → POST to: <code>" . htmlspecialchars($mediaUrl, ENT_QUOTES, 'UTF-8') . "</code></p>";

            $resp = post_trigger_to_media_api($mediaUrl, $accessToken, $message, $curlVerifyPeer, $curlVerifyHost);

            echo "<h2>Triggered</h2>";
            echo "<p>Status: <strong>" . htmlspecialchars((string)$resp['status'], ENT_QUOTES, 'UTF-8') . "</strong></p>";
            echo "<details><summary>Response body</summary><pre>" . htmlspecialchars($resp['body'], ENT_QUOTES, 'UTF-8') . "</pre></details>";
            echo '<p><a href="index.php">Back</a></p>';
            exit;

        } catch (\Throwable $e) {
            http_response_code(500);
            echo "<h2>API call error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
            exit;
        }
    }

    // If some other submit came in, just ignore/do nothing special
    header('Location: index.php');
    exit;
}

/** ---------- Render minimal UI (optional) ---------- */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC Trigger Demo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; line-height: 1.5; }
    button { padding: .7rem 1rem; border: 0; border-radius: 10px; background: #0070f3; color: #fff; cursor: pointer; }
    input { padding: .6rem; border: 1px solid #ccc; border-radius: 8px; width: 100%; max-width: 540px; }
    label { display:block; margin-top:.5rem; font-weight:600; }
  </style>
</head>
<body>
  <h1>Trigger media API</h1>
  <p>Click the button to POST <code>multipart/form-data</code> with <code>attachment</code> (1 byte) and <code>message</code> (optional) using your OIDC access token.</p>

  <form method="post" action="index.php">
    <?= csrf_input(); ?>
    <label for="message">Optional message</label>
    <input id="message" name="message" placeholder="(leave empty if not needed)">
    <p><button type="submit" name="send_pdf">Send as PDF</button></p>
  </form>
</body>
</html>
