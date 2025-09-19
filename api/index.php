<?php
declare(strict_types=1);

/**
 * Stateless Keycloak OIDC (Auth Code + PKCE) + PDF upload via client_credentials (same client)
 * USER_ID in upload path = user's email (from userinfo)
 * Multipart/form-data parts:
 *   - attachment: application/pdf (filename: form.pdf)
 *   - message:    application/json (file part: message.json)
 */

$DEBUG = getenv('DEBUG') === '1';
if ($DEBUG) { ini_set('display_errors','1'); error_reporting(E_ALL); }

require __DIR__ . '/../vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

/* ---------- Load .env locally (Vercel uses env UI) ---------- */
if (class_exists(\Dotenv\Dotenv::class)) {
  \Dotenv\Dotenv::createImmutable(__DIR__ . '/..')->safeLoad();
}

/* ---------- Utilities ---------- */
function envv(string $k, $d=null){
  if (array_key_exists($k,$_ENV)) return $_ENV[$k];
  if (array_key_exists($k,$_SERVER)) return $_SERVER[$k];
  $v=getenv($k); return ($v!==false && $v!==null)?$v:$d;
}
function fail(int $code, string $msg){
  http_response_code($code);
  echo "<h2>Error</h2><pre>".htmlspecialchars($msg,ENT_QUOTES,'UTF-8')."</pre>"; exit;
}
function b64url(string $bin):string{ return rtrim(strtr(base64_encode($bin),'+/','-_'),'='); }
function rand_b64(int $n=32):string{ return b64url(random_bytes($n)); }
// Polyfills for older runtimes (Vercel is usually >=8.2, but safe anyway)
if (!function_exists('str_starts_with')) {
  function str_starts_with(string $haystack, string $needle): bool {
    return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
  }
}
if (!function_exists('str_contains')) {
  function str_contains(string $haystack, string $needle): bool {
    return $needle === '' || strpos($haystack, $needle) !== false;
  }
}

function http_get_json(string $url, array $hdr=[], bool $vp=true, bool $vh=true):array{
  $ch=curl_init($url);
  curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$hdr,
    CURLOPT_SSL_VERIFYPEER=>$vp,CURLOPT_SSL_VERIFYHOST=>$vh?2:0,CURLOPT_TIMEOUT=>30]);
  $res=curl_exec($ch); if($res===false){$e=curl_error($ch);curl_close($ch);fail(500,"GET $url failed: $e");}
  $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
  if($code<200||$code>=300) fail(500,"GET $url HTTP $code\n$res");
  $j=json_decode($res,true); if(!is_array($j)) fail(500,"GET $url not JSON"); return $j;
}
function http_post_urlenc(string $url,array $data,array $hdr=[],bool $vp=true,bool $vh=true):array{
  $ch=curl_init($url);
  curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,
    CURLOPT_POSTFIELDS=>http_build_query($data),CURLOPT_HTTPHEADER=>array_merge($hdr,['Content-Type: application/x-www-form-urlencoded']),
    CURLOPT_SSL_VERIFYPEER=>$vp,CURLOPT_SSL_VERIFYHOST=>$vh?2:0,CURLOPT_TIMEOUT=>30]);
  $res=curl_exec($ch); if($res===false){$e=curl_error($ch);curl_close($ch);fail(500,"POST $url failed: $e");}
  $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
  if($code<200||$code>=300) fail(500,"POST $url HTTP $code\n$res");
  $j=json_decode($res,true); if(!is_array($j)) fail(500,"POST $url not JSON"); return $j;
}
function http_post_form(string $url,array $fields,array $hdr=[],bool $vp=true,bool $vh=true):array{
  $ch=curl_init($url);
  curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_HEADER=>true,CURLOPT_POST=>true,
    CURLOPT_POSTFIELDS=>$fields,CURLOPT_HTTPHEADER=>$hdr,
    CURLOPT_SSL_VERIFYPEER=>$vp,CURLOPT_SSL_VERIFYHOST=>$vh?2:0,CURLOPT_TIMEOUT=>60]);
  $res=curl_exec($ch); if($res===false){$e=curl_error($ch);curl_close($ch);fail(500,"POST $url failed: $e");}
  $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); $hsz=curl_getinfo($ch,CURLINFO_HEADER_SIZE); curl_close($ch);
  return ['status'=>$code,'headers'=>substr($res,0,$hsz),'body'=>substr($res,$hsz)];
}

/* ---------- Env config ---------- */
$hostBase      = rtrim((string)envv('OIDC_PROVIDER_URL'),'/');   // e.g., https://idp.cloud.test.kobil.com
$tenant        = trim((string)envv('TENANT_NAME',''));           // realm
$clientId      = envv('OIDC_CLIENT_ID');                         // used for login AND client_credentials
$clientSecret  = envv('OIDC_CLIENT_SECRET');                     // must be set for client_credentials
$redirectUri   = envv('OIDC_REDIRECT_URI');                      // EXACT, no *
$logoutTo      = envv('OIDC_LOGOUT_REDIRECT',$redirectUri);
$serviceUuid   = envv('SERVICE_UUID');                           // for message JSON
$verifyPeer    = envv('CURL_VERIFY_PEER','1')==='1';
$verifyHost    = envv('CURL_VERIFY_HOST','1')==='1';

if(!$hostBase||!$tenant||!$clientId||!$redirectUri||!$serviceUuid){
  fail(500,"Missing env(s): OIDC_PROVIDER_URL, TENANT_NAME, OIDC_CLIENT_ID, OIDC_REDIRECT_URI, SERVICE_UUID");
}

/* ---------- Discovery (modern → legacy) ---------- */
$issuerModern = $hostBase.'/auth/realms/'.rawurlencode($tenant);
$issuerLegacy = $hostBase.'/auth/realms/'.rawurlencode($tenant);
try { $disc=http_get_json($issuerModern.'/.well-known/openid-configuration',[], $verifyPeer,$verifyHost); $issuer=$issuerModern; }
catch(\Throwable){ $disc=http_get_json($issuerLegacy.'/.well-known/openid-configuration',[], $verifyPeer,$verifyHost); $issuer=$issuerLegacy; }
$authEP  = $disc['authorization_endpoint'] ?? null;
$tokenEP = $disc['token_endpoint'] ?? null;
$userEP  = $disc['userinfo_endpoint'] ?? null;
if(!$authEP||!$tokenEP) fail(500,"Discovery missing endpoints");

/* ---------- Short-lived HttpOnly cookies (stateless) ---------- */
function set_cookie(string $n,string $v,int $ttl=600){
  setcookie($n,$v,['expires'=>time()+$ttl,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
}
function get_cookie(string $n):?string{ return isset($_COOKIE[$n])?(string)$_COOKIE[$n]:null; }
function del_cookie(string $n){ setcookie($n,'',time()-3600,'/'); }

/* ---------- CSRF for HTML form ---------- */
if (!get_cookie('csrf')) set_cookie('csrf', bin2hex(random_bytes(32)));
function csrf_input():string{ return '<input type="hidden" name="csrf" value="'.htmlspecialchars(get_cookie('csrf')??'',ENT_QUOTES,'UTF-8').'">'; }
function csrf_check():void{
  $c=get_cookie('csrf')??''; $p=$_POST['csrf']??'';
  if(!$c || !$p || !hash_equals($c,(string)$p)) fail(400,'Bad Request (CSRF)');
}

/* ---------- Step 1: start OIDC if no tokens and no code ---------- */
$code  = $_GET['code']  ?? null;
$state = $_GET['state'] ?? null;

$userAccessToken = get_cookie('at'); // stored after PRG

if (!$userAccessToken && !$code) {
  $st=rand_b64(16); $no=rand_b64(16); $ver=rand_b64(32);
  $chal=rtrim(strtr(base64_encode(hash('sha256',$ver,true)),'+/','-_'),'=');
  set_cookie('oidc_state',$st); set_cookie('oidc_nonce',$no); set_cookie('oidc_verif',$ver);
  $qs=http_build_query([
    'response_type'=>'code',
    'client_id'=>$clientId,
    'redirect_uri'=>$redirectUri,
    'scope'=>'openid profile email',   // need email in userinfo
    'state'=>$st,
    'nonce'=>$no,
    'code_challenge'=>$chal,
    'code_challenge_method'=>'S256',
  ]);
  header('Location: '.$authEP.'?'.$qs); exit;
}

/* ---------- Step 2: callback → exchange code; PRG to clean URL ---------- */
if (!$userAccessToken && $code) {
  $stc=get_cookie('oidc_state'); $ver=get_cookie('oidc_verif');
  if(!$stc || !$ver || !hash_equals($stc,(string)$state)) fail(400,'Invalid or missing state');
  del_cookie('oidc_state'); del_cookie('oidc_verif'); del_cookie('oidc_nonce');

  $post=['grant_type'=>'authorization_code','code'=>$code,'redirect_uri'=>$redirectUri,'client_id'=>$clientId,'code_verifier'=>$ver];
  if(strlen((string)$clientSecret)>0) $post['client_secret']=$clientSecret;

  $tok=http_post_urlenc($tokenEP,$post,[], $verifyPeer,$verifyHost);
  $userAccessToken = $tok['access_token'] ?? null;
  if(!$userAccessToken) fail(500,'No access_token from token endpoint');

  set_cookie('at',  $userAccessToken, 600);
  header('Location: '.$redirectUri); exit;
}

/* ---------- Step 3: we have a user access token → fetch userinfo ---------- */
if (!$userAccessToken) fail(401,'Missing access token (login was not completed)');

$ui = $userEP ? http_get_json($userEP,['Authorization: Bearer '.$userAccessToken], $verifyPeer,$verifyHost) : [];
$email      = $ui['email']       ?? '';
$givenName  = $ui['given_name']  ?? '';
$familyName = $ui['family_name'] ?? '';
$name       = $ui['name']        ?? '';

if(!$email){
  fail(500,"Missing email in userinfo. Ensure the client has the 'email' scope assigned.");
}

/* ---------- Helpers: PDF (prefer mPDF) + upload ---------- */
function make_pdf(array $d): string {
  $f = htmlspecialchars($d['first']??'', ENT_QUOTES, 'UTF-8');
  $l = htmlspecialchars($d['last'] ??'', ENT_QUOTES, 'UTF-8');
  $e = htmlspecialchars($d['email']??'', ENT_QUOTES, 'UTF-8');
  $now = date('Y-m-d H:i:s');

  $html = <<<HTML
<!doctype html><html><head><meta charset="utf-8"><style>
body{font-family:DejaVu Sans, Arial, sans-serif; margin:32px}
h1{font-size:20px} .box{border:1px solid #999; padding:16px; border-radius:8px}
.row{margin:8px 0} .lbl{font-weight:700; width:160px; display:inline-block}
.muted{color:#666; font-size:12px; margin-top:20px}
</style></head><body>
<h1>Profile Submission</h1>
<div class="box">
  <div class="row"><span class="lbl">First name:</span> {$f}</div>
  <div class="row"><span class="lbl">Last name:</span> {$l}</div>
  <div class="row"><span class="lbl">Email (User ID):</span> {$e}</div>
</div>
<p class="muted">Generated at {$now}</p>
</body></html>
HTML;

  if (class_exists('\\Mpdf\\Mpdf')) {
    $mpdf = new \Mpdf\Mpdf([
      'mode'   => 'utf-8',
      'format' => 'A4',
      // iOS tends to like embedded fonts; mPDF handles this well by default.
      'useSubstitutions' => false,
    ]);
    $mpdf->WriteHTML($html);
    return $mpdf->Output('', \Mpdf\Output\Destination::STRING_RETURN);
  } else {
    // Fallback to Dompdf if mPDF not installed
    $opts = new \Dompdf\Options(); $opts->set('isRemoteEnabled', false);
    $pdf  = new \Dompdf\Dompdf($opts);
    $pdf->loadHtml($html);
    $pdf->setPaper('A4', 'portrait');
    $pdf->render();
    return $pdf->output();
  }
}

/** Upload URL: /auth/realms/{TENANT_NAME}/mpower/v1/users/{EMAIL}/media */
function chat_url(string $hostBase,string $tenant,string $email):string{
  // If backend requires raw '@', keep as-is; otherwise encode as needed.
  return rtrim($hostBase,'/').'/auth/realms/'.$tenant.'/mpower/v1/users/'.$email.'/media';
}

/** Upload using service (client_credentials) token; message is application/json file part */
function upload_pdf_with_service_token(
  string $url,
  string $serviceAccessToken,
  string $bytes,
  string $filename,
  array  $messageObj,
  bool   $vp,
  bool   $vh
): array {
  // Temp PDF
  $tmpPdf = tmpfile(); $pdfPath = stream_get_meta_data($tmpPdf)['uri'];
  file_put_contents($pdfPath, $bytes);
  $pdfPart = new CURLFile($pdfPath, 'application/pdf', $filename);

  // Temp JSON file for 'message' with correct Content-Type
  $json = json_encode($messageObj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  $tmpJson = tmpfile(); $jsonPath = stream_get_meta_data($tmpJson)['uri'];
  file_put_contents($jsonPath, $json);
  $messageField = new CURLFile($jsonPath, 'application/json', 'message.json');

  $headers = [
    'Accept: application/json',
    'Authorization: Bearer '.$serviceAccessToken,
    // DO NOT set Content-Type here; cURL sets multipart boundary.
  ];
  $fields = [
    'attachment' => $pdfPart,
    'message'    => $messageField,
  ];
  $resp = http_post_form($url, $fields, $headers, $vp, $vh);

  fclose($tmpPdf); fclose($tmpJson);
  return $resp;
}

/* ---------- Handle POST (Send as PDF) ---------- */
if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();

  if (isset($_POST['send_pdf'])) {
    $first = trim($_POST['first_name'] ?? '') ?: $givenName;
    $last  = trim($_POST['last_name']  ?? '') ?: $familyName;
    $mail  = trim($_POST['email']      ?? '') ?: $email;   // USER_ID = email
    $msgIn = trim($_POST['message']    ?? '');

    if (!$mail) fail(500,'Email (USER_ID) is empty.');

    $pdfBytes = make_pdf(['first'=>$first,'last'=>$last,'email'=>$mail]);

    // Integrity checks (helps catch PDF issues that iOS dislikes)
    $okHeader = str_starts_with($pdfBytes, '%PDF-');
    $okEOF    = str_contains($pdfBytes, '%%EOF');
    if (!$okHeader || !$okEOF) {
      file_put_contents(sys_get_temp_dir().'/bad.pdf', $pdfBytes);
      fail(500, "Generated PDF failed integrity check.");
    }

    $endpoint = chat_url($hostBase, $tenant, $mail);

    // Use a simple ASCII filename (iOS-friendly)
    $filename = 'form.pdf';

    // Build message JSON per your spec + iOS-friendly metadata
    $messageObj = [
      "serviceUuid"    => $serviceUuid,
      "messageType"    => "attachmentMessage",
      "version"        => 3,
      "messageContent" => [
        "messageText"  => ($msgIn !== '' ? $msgIn : "Form PDF"),
        "fileName"     => $filename,
        "mimeType"     => "application/pdf",
        "sizeBytes"    => strlen($pdfBytes)
      ]
    ];

    // Fetch service token (client_credentials) using the SAME OIDC client
    if (strlen((string)$clientSecret) === 0) {
      fail(500, "CLIENT_CREDENTIALS requires OIDC_CLIENT_SECRET (your OIDC client can't be public here).");
    }
    try {
      $svcTok = http_post_urlenc($tokenEP, [
        'grant_type'    => 'client_credentials',
        'client_id'     => $clientId,
        'client_secret' => $clientSecret,
      ], [], $verifyPeer, $verifyHost);
      $serviceAccessToken = $svcTok['access_token'] ?? null;
      if (!$serviceAccessToken) throw new RuntimeException('No access_token in client_credentials response');
    } catch (\Throwable $e) {
      fail(500, "Failed to get service token: ".$e->getMessage());
    }

    // Upload
    $resp = upload_pdf_with_service_token($endpoint, $serviceAccessToken, $pdfBytes, $filename, $messageObj, $verifyPeer, $verifyHost);

    echo "<h2>Uploaded</h2>";
    echo "<p>Endpoint: <code>".htmlspecialchars($endpoint,ENT_QUOTES,'UTF-8')."</code></p>";
    echo "<p>Status: <strong>".htmlspecialchars((string)$resp['status'],ENT_QUOTES,'UTF-8')."</strong></p>";
    echo "<details open><summary>Response headers</summary><pre>".htmlspecialchars($resp['headers'],ENT_QUOTES,'UTF-8')."</pre></details>";
    echo "<details open><summary>Response body</summary><pre>".htmlspecialchars($resp['body'],ENT_QUOTES,'UTF-8')."</pre></details>";
    echo '<p><a href="'.htmlspecialchars($redirectUri,ENT_QUOTES,'UTF-8').'">Back</a></p>';
    exit;
  }

  header('Location: '.$redirectUri); exit;
}

/* ---------- Render UI ---------- */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC → Prefilled Form → Send as PDF (mPDF)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:2rem;line-height:1.5}
    form{max-width:560px;display:grid;gap:1rem}
    label{font-weight:600}
    input,textarea{padding:.6rem;border:1px solid #ccc;border-radius:8px;width:100%}
    button{padding:.7rem 1rem;border:0;border-radius:10px;cursor:pointer;background:#0070f3;color:#fff}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
    .topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem}
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

    <label for="message">Message text (optional)</label>
    <textarea id="message" name="message" rows="3" placeholder="(leave empty to use 'Form PDF')">Form PDF</textarea>

    <button type="submit" name="send_pdf">Send as PDF</button>
  </form>
</body>
</html>
