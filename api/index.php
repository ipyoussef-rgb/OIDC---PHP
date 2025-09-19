<?php
declare(strict_types=1);

/** ===== Debug toggle ===== */
$DEBUG = getenv('DEBUG') === '1';
if ($DEBUG) { ini_set('display_errors','1'); error_reporting(E_ALL); }

/** ===== Autoload ===== */
require __DIR__ . '/../vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

/** ===== Load .env locally (Vercel uses env UI) ===== */
if (class_exists(\Dotenv\Dotenv::class)) {
  \Dotenv\Dotenv::createImmutable(__DIR__ . '/..')->safeLoad();
}

/** ===== Utilities ===== */
function envv(string $k, $d=null) {
  if (array_key_exists($k, $_ENV)) return $_ENV[$k];
  if (array_key_exists($k, $_SERVER)) return $_SERVER[$k];
  $v = getenv($k); return ($v!==false && $v!==null) ? $v : $d;
}
function fail(int $code, string $msg) {
  http_response_code($code);
  echo "<h2>Error</h2><pre>".htmlspecialchars($msg, ENT_QUOTES, 'UTF-8')."</pre>";
  exit;
}
function b64url_encode(string $bin): string {
  return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}
function rand_b64url(int $bytes=32): string {
  return b64url_encode(random_bytes($bytes));
}
function http_get_json(string $url, array $headers=[], bool $verifyPeer=true, bool $verifyHost=true): array {
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER=>true,
    CURLOPT_HTTPHEADER=>$headers,
    CURLOPT_SSL_VERIFYPEER=>$verifyPeer,
    CURLOPT_SSL_VERIFYHOST=>$verifyHost?2:0,
    CURLOPT_TIMEOUT=>30,
  ]);
  $res = curl_exec($ch);
  if ($res === false) { $e = curl_error($ch); curl_close($ch); fail(500, "GET $url failed: $e"); }
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  if ($code < 200 || $code >= 300) fail(500, "GET $url returned HTTP $code\n$res");
  $json = json_decode($res, true);
  if (!is_array($json)) fail(500, "GET $url did not return JSON.");
  return $json;
}
function http_post_form(string $url, array $fields, array $headers=[], bool $verifyPeer=true, bool $verifyHost=true): array {
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER=>true,
    CURLOPT_HEADER=>true,
    CURLOPT_POST=>true,
    CURLOPT_POSTFIELDS=>$fields,
    CURLOPT_HTTPHEADER=>$headers,
    CURLOPT_SSL_VERIFYPEER=>$verifyPeer,
    CURLOPT_SSL_VERIFYHOST=>$verifyHost?2:0,
    CURLOPT_TIMEOUT=>60,
  ]);
  $res = curl_exec($ch);
  if ($res === false) { $e = curl_error($ch); curl_close($ch); fail(500, "POST $url failed: $e"); }
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $hsz  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  curl_close($ch);
  return ['status'=>$code, 'headers'=>substr($res,0,$hsz), 'body'=>substr($res,$hsz)];
}
function http_post_urlencoded(string $url, array $data, array $headers=[], bool $verifyPeer=true, bool $verifyHost=true): array {
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER=>true,
    CURLOPT_POST=>true,
    CURLOPT_POSTFIELDS=>http_build_query($data),
    CURLOPT_HTTPHEADER=>array_merge($headers, ['Content-Type: application/x-www-form-urlencoded']),
    CURLOPT_SSL_VERIFYPEER=>$verifyPeer,
    CURLOPT_SSL_VERIFYHOST=>$verifyHost?2:0,
    CURLOPT_TIMEOUT=>30,
  ]);
  $res = curl_exec($ch);
  if ($res === false) { $e = curl_error($ch); curl_close($ch); fail(500, "POST $url failed: $e"); }
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  if ($code < 200 || $code >= 300) fail(500, "Token endpoint HTTP $code\n$res");
  $json = json_decode($res, true);
  if (!is_array($json)) fail(500, "Token endpoint did not return JSON.");
  return $json;
}

/** ===== Config from env ===== */
$hostBase      = rtrim((string)envv('OIDC_PROVIDER_URL'), '/');   // e.g. https://idp.example.com
$tenant        = trim((string)envv('TENANT_NAME',''));            // e.g. worms
$clientId      = envv('OIDC_CLIENT_ID');
$clientSecret  = envv('OIDC_CLIENT_SECRET');                      // may be empty for public client + PKCE
$redirectUri   = envv('OIDC_REDIRECT_URI');                       // EXACT deployed URL (no wildcard)
$logoutTo      = envv('OIDC_LOGOUT_REDIRECT', '/');
$verifyPeer    = envv('CURL_VERIFY_PEER','1')==='1';
$verifyHost    = envv('CURL_VERIFY_HOST','1')==='1';

if (!$hostBase || !$tenant || !$clientId || !$redirectUri) {
  fail(500, "Missing env: OIDC_PROVIDER_URL(host base), TENANT_NAME, OIDC_CLIENT_ID, OIDC_REDIRECT_URI");
}

/** ===== Build realm issuer (modern & legacy), discover endpoints ===== */
$issuerModern = $hostBase . '/auth/realms/' . rawurlencode($tenant);
$issuerLegacy = $hostBase . '/auth/realms/' . rawurlencode($tenant);

$discovery = null;
$issuerUsed = null;
try {
  $discovery = http_get_json($issuerModern.'/.well-known/openid-configuration', [], $verifyPeer, $verifyHost);
  $issuerUsed = $issuerModern;
} catch (\Throwable $e) {
  $discovery = http_get_json($issuerLegacy.'/.well-known/openid-configuration', [], $verifyPeer, $verifyHost);
  $issuerUsed = $issuerLegacy;
}

$authEndpoint  = $discovery['authorization_endpoint'] ?? null;
$tokenEndpoint = $discovery['token_endpoint'] ?? null;
$userinfoEP    = $discovery['userinfo_endpoint'] ?? null;
if (!$authEndpoint || !$tokenEndpoint) {
  fail(500, "Discovery missing endpoints.");
}

/** ===== Cookie helpers for stateless flow ===== */
function set_cookie(string $name, string $val, int $ttl=600): void {
  setcookie($name, $val, [
    'expires'=> time()+$ttl,
    'path'   => '/',
    'secure' => true,
    'httponly'=> true,
    'samesite'=> 'Lax',
  ]);
}
function get_cookie(string $name): ?string {
  return isset($_COOKIE[$name]) ? (string)$_COOKIE[$name] : null;
}
function del_cookie(string $name): void {
  setcookie($name, '', time()-3600, '/');
}

/** ===== CSRF for the HTML form ===== */
if (!get_cookie('csrf')) { set_cookie('csrf', bin2hex(random_bytes(32))); }
function csrf_input(): string {
  $v = htmlspecialchars(get_cookie('csrf') ?? '', ENT_QUOTES, 'UTF-8');
  return '<input type="hidden" name="csrf" value="'.$v.'">';
}
function check_csrf(): void {
  $cookie = get_cookie('csrf') ?? '';
  $posted = $_POST['csrf'] ?? '';
  if (!$cookie || !$posted || !hash_equals($cookie, (string)$posted)) fail(400, 'Bad Request (CSRF)');
}

/** ===== Begin OIDC Authorization Code + PKCE ===== */
$code  = $_GET['code']  ?? null;
$state = $_GET['state'] ?? null;

if (!$code) {
  // Start login
  $stateVal  = rand_b64url(16);
  $nonceVal  = rand_b64url(16);
  $verifier  = rand_b64url(32);
  $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

  set_cookie('oidc_state',  $stateVal);
  set_cookie('oidc_nonce',  $nonceVal);
  set_cookie('oidc_verif',  $verifier);

  $params = [
    'response_type' => 'code',
    'client_id'     => $clientId,
    'redirect_uri'  => $redirectUri,
    'scope'         => 'openid profile email',
    'state'         => $stateVal,
    'nonce'         => $nonceVal,
    'code_challenge' => $challenge,
    'code_challenge_method' => 'S256',
  ];

  // Build auth URL
  $authUrl = $authEndpoint . '?' . http_build_query($params);
  header('Location: ' . $authUrl);
  exit;
}

// Callback: validate state, exchange code
$stateCookie = get_cookie('oidc_state');
$verifier    = get_cookie('oidc_verif');
if (!$stateCookie || !$verifier || !hash_equals($stateCookie, (string)$state)) {
  fail(400, "Invalid or missing state.");
}
del_cookie('oidc_state'); // one-time

// Exchange code for tokens
$post = [
  'grant_type'    => 'authorization_code',
  'code'          => $code,
  'redirect_uri'  => $redirectUri,
  'client_id'     => $clientId,
  'code_verifier' => $verifier,
];
// Use client_secret only if confidential client
if (strlen((string)$clientSecret) > 0) {
  $post['client_secret'] = $clientSecret;
}

$token = http_post_urlencoded($tokenEndpoint, $post, [], $verifyPeer, $verifyHost);
$accessToken = $token['access_token'] ?? null;
if (!$accessToken) fail(500, "No access_token from token endpoint.");

// Fetch userinfo
$headers = ['Authorization: Bearer '.$accessToken];
$userinfo = $userinfoEP ? http_get_json($userinfoEP, $headers, $verifyPeer, $verifyHost) : [];
$email      = $userinfo['email']       ?? '';
$givenName  = $userinfo['given_name']  ?? '';
$familyName = $userinfo['family_name'] ?? '';
$name       = $userinfo['name']        ?? '';

if (!$email) {
  // Some IdPs need email scope assigned or return in different claim
  fail(500, "Missing email in userinfo. Ensure 'email' scope is assigned to the client.");
}
if (!$givenName && !$familyName && $name) {
  $parts = preg_split('/\s+/', $name, 2);
  $givenName  = $parts[0] ?? '';
  $familyName = $parts[1] ?? '';
}

/** ===== Helpers: PDF + Chat API upload ===== */
function make_pdf_from_form(array $data): string {
  $first = htmlspecialchars($data['first_name'] ?? '', ENT_QUOTES, 'UTF-8');
  $last  = htmlspecialchars($data['last_name'] ?? '',  ENT_QUOTES, 'UTF-8');
  $email = htmlspecialchars($data['email'] ?? '',      ENT_QUOTES, 'UTF-8');
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

  $opts = new Options(); $opts->set('isRemoteEnabled', false);
  $dompdf = new Dompdf($opts);
  $dompdf->loadHtml($html);
  $dompdf->setPaper('A4', 'portrait');
  $dompdf->render();
  return $dompdf->output();
}

function chat_api_url(string $hostBase, string $tenant, string $userEmail): string {
  $base = rtrim($hostBase, '/');
  // Per your spec: always /auth/realms/{TENANT_NAME}
  return $base . '/auth/realms/' . rawurlencode($tenant) . '/mpower/v1/users/' . rawurlencode($userEmail) . '/media';
}

function upload_pdf_to_chat_api(string $url, string $accessToken, string $pdfBytes, string $filename, string $message, bool $verifyPeer=true, bool $verifyHost=true): array {
  $tmp = tmpfile();
  $tmpPath = stream_get_meta_data($tmp)['uri'];
  file_put_contents($tmpPath, $pdfBytes);
  $cfile = new CURLFile($tmpPath, 'application/pdf', $filename);

  $headers = [
    'Accept: application/json',
    'Authorization: Bearer '.$accessToken,
    // DO NOT set Content-Type; cURL will set multipart boundary.
  ];
  $fields = [
    'attachment' => $cfile,
    'message'    => $message,
  ];

  $resp = http_post_form($url, $fields, $headers, $verifyPeer, $verifyHost);
  fclose($tmp);
  return $resp;
}

/** ===== Handle form POST (Send as PDF) ===== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // CSRF
  $cookieCsrf = get_cookie('csrf') ?? '';
  $postedCsrf = $_POST['csrf'] ?? '';
  if (!$cookieCsrf || !$postedCsrf || !hash_equals($cookieCsrf, (string)$postedCsrf)) {
    fail(400, 'Bad Request (CSRF)');
  }

  if (isset($_POST['send_pdf'])) {
    $firstName = trim($_POST['first_name'] ?? '') ?: $givenName;
    $lastName  = trim($_POST['last_name']  ?? '') ?: $familyName;
    $emailForm = trim($_POST['email']      ?? '') ?: $email;
    $message   = trim($_POST['message']    ?? '');

    if (!$emailForm) fail(500, 'Email (USER_ID) is empty.');

    $pdf = make_pdf_from_form([
      'first_name' => $firstName,
      'last_name'  => $lastName,
      'email'      => $emailForm,
    ]);
    $endpoint = chat_api_url($hostBase, $tenant, $emailForm);
    $res = upload_pdf_to_chat_api($endpoint, $accessToken, $pdf, 'profile-'.date('Ymd-His').'.pdf', $message, $verifyPeer, $verifyHost);

    echo "<h2>Uploaded</h2>";
    echo "<p>Endpoint: <code>".htmlspecialchars($endpoint,ENT_QUOTES,'UTF-8')."</code></p>";
    echo "<p>Status: <strong>".htmlspecialchars((string)$res['status'],ENT_QUOTES,'UTF-8')."</strong></p>";
    echo "<details><summary>Response body</summary><pre>".htmlspecialchars($res['body'],ENT_QUOTES,'UTF-8')."</pre></details>";
    echo '<p><a href="'.htmlspecialchars($redirectUri,ENT_QUOTES,'UTF-8').'">Back</a></p>';
    exit;
  }

  header('Location: '.$redirectUri);
  exit;
}

/** ===== Render UI ===== */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC → Prefilled Form → Send as PDF (stateless)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; line-height: 1.5; }
    form { max-width: 560px; display: grid; gap: 1rem; }
    label { font-weight: 600; }
    input, textarea { padding: .6rem; border: 1px solid #ccc; border-radius: 8px; width: 100%; }
    button { padding: .7rem 1rem; border: 0; border-radius: 10px; cursor: pointer; background: #0070f3; color: #fff; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .topbar { display:flex; justify-content: space-between; align-items:center; margin-bottom:1.25rem; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>Welcome <?= htmlspecialchars($givenName ?: 'User', ENT_QUOTES, 'UTF-8'); ?> 👋</h1>
    <a href="<?= htmlspecialchars($logoutTo, ENT_QUOTES, 'UTF-8'); ?>"><button>Logout</button></a>
  </div>

  <form method="post" action="">
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

    <label for="email">Email (used as USER_ID)</label>
    <input id="email" type="email" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>">

    <label for="message">Optional message</label>
    <textarea id="message" name="message" rows="3" placeholder="(leave empty if not needed)"></textarea>

    <button type="submit" name="send_pdf">Send as PDF</button>
  </form>
</body>
</html>
