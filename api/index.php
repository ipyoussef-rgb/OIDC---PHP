<?php
declare(strict_types=1);
session_start();

require __DIR__ . '/../vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;
use Dompdf\Dompdf;
use Dompdf\Options;

/**
 * Load .env (requires: composer require vlucas/phpdotenv)
 * Place .env at project root (one level above /api), e.g.:
 * C:\xampp\htdocs\oidc-php\.env
 */
if (class_exists(\Dotenv\Dotenv::class)) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->safeLoad();
}

/**
 * env() helper: read from $_ENV/$_SERVER/getenv with a default.
 */
function env(string $key, $default = null) {
    if (array_key_exists($key, $_ENV))    return $_ENV[$key];
    if (array_key_exists($key, $_SERVER)) return $_SERVER[$key];
    $v = getenv($key);
    return ($v !== false && $v !== null) ? $v : $default;
}

/** ----------------------- Read config ----------------------- */
// OIDC + app config
$providerUrl    = env('OIDC_PROVIDER_URL');                 // e.g. https://host/realms/<realm>  OR  https://host/auth/realms/<realm>
$clientId       = env('OIDC_CLIENT_ID');
$clientSecret   = env('OIDC_CLIENT_SECRET');                // empty if client is PUBLIC
$redirectUri    = env('OIDC_REDIRECT_URI', 'http://localhost/oidc-php/');
$logoutRedirect = env('OIDC_LOGOUT_REDIRECT', '/');

// PDF + API posting
// If USER_ID not provided, we'll default to the OIDC subject (sub) after login.
$forceUserId    = env('USER_ID');                           // optional override
// For some setups, the API may be on the same host as Keycloak PATH. We’ll derive from $providerUrl.
$curlVerifyPeer = env('CURL_VERIFY_PEER', '1') === '1';     // set to "0" only for local testing of self-signed certs
$curlVerifyHost = env('CURL_VERIFY_HOST', '1') === '1';     // set to "0" only for local testing

// Fail fast if essential OIDC vars missing
if (!$providerUrl || !$clientId) {
    http_response_code(500);
    echo "<h2>Configuration error</h2><pre>";
    echo "Missing OIDC_PROVIDER_URL or OIDC_CLIENT_ID.\n";
    echo "Check that .env exists at project root and Dotenv is installed.\n\n";
    echo "providerUrl = " . var_export($providerUrl, true) . "\n";
    echo "clientId    = " . var_export($clientId, true) . "\n";
    echo "</pre>";
    exit;
}

/** ----------------------- CSRF helpers ----------------------- */
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
function csrf_input(): string {
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8') . '">';
}
function check_csrf(): void {
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
        http_response_code(400);
        exit('Bad Request (CSRF)');
    }
}

/** ----------------------- Logout ----------------------- */
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

/** ----------------------- Authenticate (OIDC) ----------------------- */
try {
    $oidc = new OpenIDConnectClient(
        $providerUrl,
        $clientId,
        $clientSecret
    );

    $oidc->setRedirectURL($redirectUri);
    $oidc->addScope(['profile', 'email', 'roles']);

    // If your IdP test certs cause SSL issues locally, you can (TEMPORARILY) relax verify:
    // $oidc->setVerifyPeer(false);
    // $oidc->setVerifyHost(false);

    // (Optional) If discovery fails in your environment, uncomment and set endpoints manually:
    // $kcBase = rtrim($providerUrl, '/');
    // $oidc->setAuthorizationEndpoint($kcBase . '/protocol/openid-connect/auth');
    // $oidc->setTokenEndpoint($kcBase . '/protocol/openid-connect/token');
    // $oidc->setUserInfoEndpoint($kcBase . '/protocol/openid-connect/userinfo');
    // $oidc->setEndSessionEndpoint($kcBase . '/protocol/openid-connect/logout');
    // $oidc->setJwksUri($kcBase . '/protocol/openid-connect/certs');

    $oidc->authenticate();

    // Pull tokens & claims
    $accessToken   = $oidc->getAccessToken();              // Bearer token to call your API
    $idTokenClaims = $oidc->getVerifiedClaims();           // from ID token
    $userinfo      = $oidc->requestUserInfo();             // from /userinfo
    $claims        = array_merge((array)$idTokenClaims, (array)$userinfo);

    // Map to form fields
    $email      = $claims['email']        ?? '';
    $givenName  = $claims['given_name']   ?? '';
    $familyName = $claims['family_name']  ?? '';
    $name       = $claims['name']         ?? '';
    $subject    = $claims['sub']          ?? null;         // typically the user UUID in Keycloak

    if (!$givenName && !$familyName && $name) {
        $parts = preg_split('/\s+/', $name, 2);
        $givenName  = $parts[0] ?? '';
        $familyName = $parts[1] ?? '';
    }

} catch (Throwable $e) {
    http_response_code(500);
    echo "<h2>Login error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
    error_log("OIDC error: " . $e->getMessage());
    error_log("Provider: $providerUrl ; Redirect: $redirectUri");
    exit;
}

/** ----------------------- Helper: build API URL ----------------------- */
/**
 * We accept either issuer base formats:
 *  - https://host/realms/<realm>
 *  - https://host/auth/realms/<realm>
 * We extract up to ".../realms/<realm>" and append the mpower path.
 */
function build_media_api_url(string $providerUrl, string $userId): string {
    $u = parse_url($providerUrl);
    if (!$u || empty($u['scheme']) || empty($u['host'])) {
        throw new RuntimeException("Invalid OIDC_PROVIDER_URL for deriving API URL.");
    }
    $scheme = $u['scheme'];
    $host   = $u['host'];
    $port   = isset($u['port']) ? ':' . $u['port'] : '';
    $path   = rtrim($u['path'] ?? '', '/'); // should contain /realms/<realm> or /auth/realms/<realm>

    // Normalize: if $path includes '/.well-known/...' strip it
    if (str_contains($path, '/.well-known/')) {
        $path = preg_replace('#/\.well-known/.*$#', '', $path);
    }

    // Ensure it ends with /realms/<realm>
    if (!preg_match('#/(?:auth/)?realms/[^/]+$#', $path)) {
        throw new RuntimeException("Cannot derive realm from OIDC_PROVIDER_URL path: $path");
    }

    // Compose API endpoint:
    // /auth/realms/{TENANT_NAME}/mpower/v1/users/{USER_ID}/media  OR without /auth if not used by your server
    // Keep exactly the prefix we detected in $path to match your environment.
    $base = $scheme . '://' . $host . $port . $path;

    return $base . '/mpower/v1/users/' . rawurlencode($userId) . '/media';
}

/** ----------------------- Helper: generate PDF bytes ----------------------- */
function make_pdf_from_form(array $data): string {
    $first = htmlspecialchars($data['first_name'] ?? '', ENT_QUOTES, 'UTF-8');
    $last  = htmlspecialchars($data['last_name'] ?? '', ENT_QUOTES, 'UTF-8');
    $email = htmlspecialchars($data['email'] ?? '', ENT_QUOTES, 'UTF-8');
    $now   = date('Y-m-d H:i:s');

    $html = <<<HTML
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: DejaVu Sans, Arial, sans-serif; margin: 32px; }
    h1 { font-size: 20px; }
    .box { border: 1px solid #999; padding: 16px; border-radius: 8px; }
    .row { margin: 8px 0; }
    .lbl { font-weight: bold; width: 140px; display: inline-block; }
    .muted { color:#666; font-size: 12px; margin-top: 20px; }
  </style>
</head>
<body>
  <h1>Profile Submission</h1>
  <div class="box">
    <div class="row"><span class="lbl">First name:</span> {$first}</div>
    <div class="row"><span class="lbl">Last name:</span> {$last}</div>
    <div class="row"><span class="lbl">Email:</span> {$email}</div>
  </div>
  <p class="muted">Generated at {$now}</p>
</body>
</html>
HTML;

    $options = new Options();
    $options->set('isRemoteEnabled', false);
    $dompdf = new Dompdf($options);
    $dompdf->loadHtml($html);
    $dompdf->setPaper('A4', 'portrait');
    $dompdf->render();
    return $dompdf->output(); // raw PDF bytes
}

/** ----------------------- Helper: POST file to API with Bearer token ----------------------- */
function post_pdf_to_media_api(string $url, string $accessToken, string $pdfBytes, string $filename, bool $verifyPeer = true, bool $verifyHost = true): array {
    $tmp = tmpfile();
    $tmpPath = stream_get_meta_data($tmp)['uri'];
    file_put_contents($tmpPath, $pdfBytes);

    // Build CURLFile for multipart/form-data
    $cfile = new CURLFile($tmpPath, 'application/pdf', $filename);

    $ch = curl_init($url);
    $headers = [
        'Authorization: Bearer ' . $accessToken,
        // Some APIs require explicit content-type is multipart; cURL sets boundary automatically.
        // 'Content-Type: multipart/form-data' // not needed explicitly
    ];
    $postFields = [
        // The parameter name your API expects. If different, change 'file' to that name.
        'file' => $cfile,
        // Optional metadata fields if your API supports them:
        // 'title' => 'Profile Submission PDF',
        // 'description' => 'Generated from OIDC PHP form',
    ];

    curl_setopt_array($ch, [
        CURLOPT_POST            => true,
        CURLOPT_POSTFIELDS      => $postFields,
        CURLOPT_HTTPHEADER      => $headers,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_HEADER          => true, // to parse status
        CURLOPT_SSL_VERIFYPEER  => $verifyPeer,
        CURLOPT_SSL_VERIFYHOST  => $verifyHost ? 2 : 0,
        CURLOPT_TIMEOUT         => 60,
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

    return [
        'status'  => $status,
        'headers' => $rawHeaders,
        'body'    => $body,
    ];
}

/** ----------------------- Handle POST actions ----------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $firstName = trim($_POST['first_name'] ?? '');
    $lastName  = trim($_POST['last_name']  ?? '');
    $emailForm = trim($_POST['email']      ?? '');

    // If clicked "Send as PDF", we'll generate + upload
    if (isset($_POST['send_pdf'])) {

        // Determine USER_ID for the API
        $userId = $forceUserId ?: ($subject ?? null);
        if (!$userId) {
            http_response_code(500);
            echo "<h2>Cannot determine USER_ID</h2><p>No USER_ID env and no 'sub' claim in token.</p>";
            exit;
        }

        // Build URL: {issuerBase}/mpower/v1/users/{USER_ID}/media (keeps /auth prefix if present)
        try {
            $mediaUrl = build_media_api_url($providerUrl, $userId);
            echo "<p>DEBUG → Will POST PDF to: <code>" . htmlspecialchars($mediaUrl, ENT_QUOTES, 'UTF-8') . "</code></p>";

        } catch (Throwable $e) {
            http_response_code(500);
            echo "<h2>API URL error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
            exit;
        }

        // Create PDF
        try {
            $pdfBytes = make_pdf_from_form([
                'first_name' => $firstName,
                'last_name'  => $lastName,
                'email'      => $emailForm ?: ($email ?? ''),
            ]);
        } catch (Throwable $e) {
            http_response_code(500);
            echo "<h2>PDF generation error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
            exit;
        }

        // Upload to API using OIDC access token
        try {
            $filename = 'profile-' . date('Ymd-His') . '.pdf';
            $resp = post_pdf_to_media_api($mediaUrl, $accessToken, $pdfBytes, $filename, $curlVerifyPeer, $curlVerifyHost);

            echo "<h2>PDF sent</h2>";
            echo "<p>Status: <strong>" . htmlspecialchars((string)$resp['status'], ENT_QUOTES, 'UTF-8') . "</strong></p>";
            echo "<details><summary>Response body</summary><pre>" . htmlspecialchars($resp['body'], ENT_QUOTES, 'UTF-8') . "</pre></details>";
            echo '<p><a href="index.php">Back</a></p>';
            exit;

        } catch (Throwable $e) {
            http_response_code(500);
            echo "<h2>Upload error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
            echo "<p>Endpoint tried: <code>" . htmlspecialchars($mediaUrl, ENT_QUOTES, 'UTF-8') . "</code></p>";
            exit;
        }
    }

    // Otherwise just echo values (normal Save)
    echo "<h2>Saved values</h2><pre>" . htmlspecialchars(print_r([
        'first_name' => $firstName,
        'last_name'  => $lastName,
        'email'      => $emailForm,
    ], true), ENT_QUOTES, 'UTF-8') . "</pre>";
    echo '<p><a href="index.php">Back</a></p>';
    exit;
}

/** ----------------------- Render HTML ----------------------- */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC PHP Demo (Keycloak) + Send PDF</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; line-height: 1.5; }
    form { max-width: 540px; display: grid; gap: 1rem; }
    label { font-weight: 600; }
    input { padding: 0.6rem; border: 1px solid #ccc; border-radius: 8px; width: 100%; }
    button { padding: 0.7rem 1rem; border: 0; border-radius: 10px; cursor: pointer; }
    .primary { background: #0070f3; color: #fff; }
    .ghost { background: transparent; border: 1px solid #999; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .topbar { display:flex; justify-content: space-between; align-items:center; margin-bottom:1.5rem; }
    .muted { color:#666; font-size: .9rem; }
    details { margin-top: 1.25rem; }
    pre { white-space: pre-wrap; word-wrap: break-word; }
    .actions { display:flex; gap: .5rem; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>Welcome <?= htmlspecialchars($givenName ?: 'User', ENT_QUOTES, 'UTF-8'); ?> 👋</h1>
    <a href="?action=logout"><button class="ghost">Logout</button></a>
  </div>

  <p class="muted">You’re authenticated via OpenID Connect. Update your details, then click “Send as PDF” to upload to your API.</p>

  <form method="post" action="index.php" autocomplete="on">
    <?= csrf_input(); ?>
    <div class="row">
      <div>
        <label for="first_name">First name</label>
        <input id="first_name" name="first_name" value="<?= htmlspecialchars($givenName, ENT_QUOTES, 'UTF-8'); ?>">
      </div>
      <div>
        <label for="last_name">Last name</label>
        <input id="last_name" name="last_name" value="<?= htmlspecialchars($familyName, ENT_QUOTES, 'UTF-8'); ?>">
      </div>
    </div>

    <label for="email">Email</label>
    <input id="email" type="email" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>">

    <div class="actions">
      <button type="submit" name="save" class="ghost">Save</button>
      <button type="submit" name="send_pdf" class="primary">Send as PDF</button>
    </div>
  </form>

  <details>
    <summary>Debug: raw claims</summary>
    <pre><?= htmlspecialchars(print_r($claims, true), ENT_QUOTES, 'UTF-8'); ?></pre>
  </details>
</body>
</html>
