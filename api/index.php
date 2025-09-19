<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;
use Dompdf\Dompdf;
use Dompdf\Options;

/**
 * Load .env locally; on Vercel set env vars in the dashboard.
 */
if (class_exists(\Dotenv\Dotenv::class)) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->safeLoad();
}

/** Small env helper that checks $_ENV/$_SERVER/getenv */
function env(string $key, $default = null) {
    if (array_key_exists($key, $_ENV))    return $_ENV[$key];
    if (array_key_exists($key, $_SERVER)) return $_SERVER[$key];
    $v = getenv($key);
    return ($v !== false && $v !== null) ? $v : $default;
}

session_start();

/** ===== Config ===== */
$providerBase   = rtrim((string)env('OIDC_PROVIDER_URL'), '/');   // e.g. https://idp.example.com
$clientId       = env('OIDC_CLIENT_ID');
$clientSecret   = env('OIDC_CLIENT_SECRET');                      // empty if client is public
$redirectUri    = env('OIDC_REDIRECT_URI', 'http://localhost/oidc-php/');
$logoutRedirect = env('OIDC_LOGOUT_REDIRECT', '/');
$tenantName     = env('TENANT_NAME');                             // REQUIRED for /auth/realms/{TENANT_NAME}/...

$curlVerifyPeer = env('CURL_VERIFY_PEER', '1') === '1';
$curlVerifyHost = env('CURL_VERIFY_HOST', '1') === '1';

if (!$providerBase || !$clientId || !$redirectUri || !$tenantName) {
    http_response_code(500);
    echo "<h2>Configuration error</h2><pre>" .
         "OIDC_PROVIDER_URL, OIDC_CLIENT_ID, OIDC_REDIRECT_URI, TENANT_NAME are required.\n" .
         "OIDC_PROVIDER_URL=" . var_export($providerBase, true) . "\n" .
         "OIDC_CLIENT_ID="    . var_export($clientId, true)    . "\n" .
         "OIDC_REDIRECT_URI=" . var_export($redirectUri, true) . "\n" .
         "TENANT_NAME="       . var_export($tenantName, true)  . "\n" .
         "</pre>";
    exit;
}

/** ===== CSRF helpers ===== */
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
function csrf_input(): string {
    return '<input type="hidden" name="csrf" value="' . htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8') . '">';
}
function check_csrf(): void {
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'])) {
        http_response_code(400); exit('Bad Request (CSRF)');
    }
}

/** ===== Logout ===== */
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

/** ===== OIDC authenticate (Keycloak) ===== */
try {
    /**
     * For discovery, we need the issuer (realm) URL. You gave $OIDC_PROVIDER_URL as host base.
     * For Keycloak, the realm issuer is: {host}/realms/{TENANT}  OR  {host}/auth/realms/{TENANT}.
     * We'll try modern first, then legacy, and let the client discover.
     */
    $issuerModern = $providerBase . '/realms/' . rawurlencode($tenantName);
    $issuerLegacy = $providerBase . '/auth/realms/' . rawurlencode($tenantName);

    // Try modern first; if it fails in authenticate step, we’ll retry legacy once.
    $issuerTried  = $issuerModern;
    $oidc = new OpenIDConnectClient($issuerTried, $clientId, $clientSecret);
    $oidc->setRedirectURL($redirectUri);

    // Request scopes as an ARRAY (your library expects array).
    // If your realm rejects profile/email, change to ['openid'].
    $oidc->addScope(['openid', 'profile', 'email']);

    $tryAuth = function(OpenIDConnectClient $client) {
        $client->authenticate();
    };

    try {
        $tryAuth($oidc);
    } catch (\Throwable $e1) {
        // Retry once with legacy /auth issuer
        $issuerTried = $issuerLegacy;
        $oidc = new OpenIDConnectClient($issuerTried, $clientId, $clientSecret);
        $oidc->setRedirectURL($redirectUri);
        $oidc->addScope(['openid', 'profile', 'email']);
        $tryAuth($oidc);
    }

    $accessToken   = $oidc->getAccessToken();
    $idTokenClaims = $oidc->getVerifiedClaims();
    $userinfo      = $oidc->requestUserInfo();
    $claims        = array_merge((array)$idTokenClaims, (array)$userinfo);

    // We will use EMAIL as USER_ID per your requirement
    $email      = $claims['email']        ?? '';
    $givenName  = $claims['given_name']   ?? '';
    $familyName = $claims['family_name']  ?? '';
    $name       = $claims['name']         ?? '';

    if (!$email) {
        http_response_code(500);
        echo "<h2>Missing email</h2><p>The token/userinfo did not include 'email'. Ensure the client has the 'email' scope assigned.</p>";
        exit;
    }
    if (!$givenName && !$familyName && $name) {
        $parts = preg_split('/\s+/', $name, 2);
        $givenName  = $parts[0] ?? '';
        $familyName = $parts[1] ?? '';
    }

} catch (\Throwable $e) {
    http_response_code(500);
    echo "<h2>Login error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
    exit;
}

/** ===== Helpers ===== */

/** Build EXACT Chat API endpoint:
 *  {providerBase}/auth/realms/{TENANT_NAME}/mpower/v1/users/{USER_ID}/media
 *  (always using /auth/realms per your spec)
 */
function build_chat_api_url(string $providerBase, string $tenant, string $userEmail): string {
    $base = rtrim($providerBase, '/'); // host base only
    return $base . '/auth/realms/' . rawurlencode($tenant) . '/mpower/v1/users/' . rawurlencode($userEmail) . '/media';
}

/** Make a simple PDF from current form values */
function make_pdf_from_form(array $data): string {
    $first = htmlspecialchars($data['first_name'] ?? '', ENT_QUOTES, 'UTF-8');
    $last  = htmlspecialchars($data['last_name'] ?? '', ENT_QUOTES, 'UTF-8');
    $email = htmlspecialchars($data['email'] ?? '', ENT_QUOTES, 'UTF-8');
    $now   = date('Y-m-d H:i:s');

    $html = <<<HTML
<!doctype html>
<html><head><meta charset="utf-8">
<style>
  body { font-family: DejaVu Sans, Arial, sans-serif; margin: 32px; }
  h1 { font-size: 20px; }
  .box { border: 1px solid #999; padding: 16px; border-radius: 8px; }
  .row { margin: 8px 0; }
  .lbl { font-weight: bold; width: 140px; display: inline-block; }
  .muted { color:#666; font-size: 12px; margin-top: 20px; }
</style></head>
<body>
  <h1>Profile Submission</h1>
  <div class="box">
    <div class="row"><span class="lbl">First name:</span> {$first}</div>
    <div class="row"><span class="lbl">Last name:</span> {$last}</div>
    <div class="row"><span class="lbl">Email (User ID):</span> {$email}</div>
  </div>
  <p class="muted">Generated at {$now}</p>
</body></html>
HTML;

    $options = new Options();
    $options->set('isRemoteEnabled', false);
    $dompdf = new Dompdf($options);
    $dompdf->loadHtml($html);
    $dompdf->setPaper('A4', 'portrait');
    $dompdf->render();
    return $dompdf->output(); // raw PDF bytes
}

/** Upload PDF via multipart/form-data (attachment + message) with Bearer token */
function post_pdf_to_media_api(
    string $url,
    string $accessToken,
    string $pdfBytes,
    string $filename,
    string $message = '',
    bool $verifyPeer = true,
    bool $verifyHost = true
): array {
    $tmp = tmpfile();
    $tmpPath = stream_get_meta_data($tmp)['uri'];
    file_put_contents($tmpPath, $pdfBytes);
    $cfile = new CURLFile($tmpPath, 'application/pdf', $filename);

    $ch = curl_init($url);
    $headers = [
        'Accept: application/json',
        'Authorization: Bearer ' . $accessToken,
        // DO NOT set Content-Type manually; cURL will set the correct multipart boundary.
    ];
    $postFields = [
        'attachment' => $cfile,
        'message'    => $message,
    ];

    curl_setopt_array($ch, [
        CURLOPT_POST            => true,
        CURLOPT_POSTFIELDS      => $postFields,
        CURLOPT_HTTPHEADER      => $headers,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_HEADER          => true,
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

    return ['status' => $status, 'headers' => $rawHeaders, 'body' => $body];
}

/** ===== Handle POST (Send as PDF) ===== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();

    if (isset($_POST['send_pdf'])) {
        // Use current form values to render PDF (prefill fallback from claims)
        $firstName = trim($_POST['first_name'] ?? '') ?: ($givenName ?? '');
        $lastName  = trim($_POST['last_name']  ?? '') ?: ($familyName ?? '');
        $emailForm = trim($_POST['email']      ?? '') ?: ($email ?? '');
        $message   = trim($_POST['message']    ?? '');

        // USER_ID = email used to login (per your requirement)
        $userIdForPath = $emailForm;
        if (!$userIdForPath) {
            http_response_code(500);
            echo "<h2>Cannot determine USER_ID</h2><p>Email is empty; cannot build endpoint.</p>";
            exit;
        }

        // Build exact endpoint with /auth/realms/{TENANT_NAME}
        $mediaUrl = build_chat_api_url($providerBase, $tenantName, $userIdForPath);

        // Generate PDF
        try {
            $pdfBytes = make_pdf_from_form([
                'first_name' => $firstName,
                'last_name'  => $lastName,
                'email'      => $emailForm,
            ]);
        } catch (\Throwable $e) {
            http_response_code(500);
            echo "<h2>PDF generation error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
            exit;
        }

        // Upload to Chat API
        try {
            $filename = 'profile-' . date('Ymd-His') . '.pdf';
            $resp = post_pdf_to_media_api($mediaUrl, $accessToken, $pdfBytes, $filename, $message, $curlVerifyPeer, $curlVerifyHost);

            echo "<h2>Uploaded
