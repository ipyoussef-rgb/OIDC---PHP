<?php
declare(strict_types=1);

/**
 * Stateless OIDC (Auth Code + PKCE) + PDF upload
 * USER_ID in upload path = sub (subject) from userinfo/id_token/access token
 */

$DEBUG = getenv('DEBUG') === '1';
if ($DEBUG) { ini_set('display_errors','1'); error_reporting(E_ALL); }

require __DIR__ . '/../vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

/** ----- Load .env locally (Vercel uses env UI) ----- */
if (class_exists(\Dotenv\Dotenv::class)) {
  \Dotenv\Dotenv::createImmutable(__DIR__ . '/..')->safeLoad();
}

/** ----- Utils ----- */
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
  if($code<200||$code>=300) fail(500,"Token endpoint HTTP $code\n$res");
  $j=json_decode($res,true); if(!is_array($j)) fail(500,"Token endpoint not JSON"); return $j;
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
function jwt_payload(string $jwt): ?array {
  $parts = explode('.', $jwt);
  if (count($parts) < 2) return null;
  $payload = $parts[1];
  $payload .= str_repeat('=', (4 - strlen($payload) % 4) % 4);
  $json = base64_decode(strtr($payload, '-_', '+/'));
  $arr = json_decode((string)$json, true);
  return is_array($arr) ? $arr : null;
}
function jwt_sub(?string $jwt): ?string {
  if (!$jwt) return null;
  $p = jwt_payload($jwt);
  return $p['sub'] ?? null;
}

/** ----- Env config ----- */
$hostBase      = rtrim((string)envv('OIDC_PROVIDER_URL'),'/');   // e.g., https://idp.example.com
$tenant        = trim((string)envv('TENANT_NAME',''));           // realm
$clientId      = envv('OIDC_CLIENT_ID');
$clientSecret  = envv('OIDC_CLIENT_SECRET');                     // empty if public client
$redirectUri   = envv('OIDC_REDIRECT_URI');                      // EXACT, no *
$logoutTo      = envv('OIDC_LOGOUT_REDIRECT',$redirectUri);
$verifyPeer    = envv('CURL_VERIFY_PEER','1')==='1';
$verifyHost    = envv('CURL_VERIFY_HOST','1')==='1';

if(!$hostBase||!$tenant||!$clientId||!$redirectUri){
  fail(500,"Missing env: OIDC_PROVIDER_URL(host base), TENANT_NAME, OIDC_CLIENT_ID, OIDC_REDIRECT_URI");
}

/** ----- Discovery (modern then legacy) ----- */
$issuerModern = $hostBase.'/auth/realms/'.rawurlencode($tenant);
$issuerLegacy = $hostBase.'/auth/realms/'.rawurlencode($tenant);
try { $disc=http_get_json($issuerModern.'/.well-known/openid-configuration',[], $verifyPeer,$verifyHost); $issuer=$issuerModern; }
catch(\Throwable){ $disc=http_get_json($issuerLegacy.'/.well-known/openid-configuration',[], $verifyPeer,$verifyHost); $issuer=$issuerLegacy; }
$authEP  = $disc['authorization_endpoint'] ?? null;
$tokenEP = $disc['token_endpoint'] ?? null;
$userEP  = $disc['userinfo_endpoint'] ?? null;
if(!$authEP||!$tokenEP) fail(500,"Discovery missing endpoints");

/** ----- Cookie helpers (HttpOnly, short-lived) ----- */
function set_cookie(string $n,string $v,int $ttl=600){
  setcookie($n,$v,['expires'=>time()+$ttl,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
}
function get_cookie(string $n):?string{ return isset($_COOKIE[$n])?(string)$_COOKIE[$n]:null; }
function del_cookie(string $n){ setcookie($n,'',time()-3600,'/'); }

/** ----- CSRF for HTML form ----- */
if (!get_cookie('csrf')) set_cookie('csrf', bin2hex(random_bytes(32)));
function csrf_input():string{ return '<input type="hidden" name="csrf" value="'.htmlspecialchars(get_cookie('csrf')??'',ENT_QUOTES,'UTF-8').'">'; }
function csrf_check():void{
  $c=get_cookie('csrf')??''; $p=$_POST['csrf']??'';
  if(!$c || !$p || !hash_equals($c,(string)$p)) fail(400,'Bad Request (CSRF)');
}

/** ----- Step 1: start OIDC if no tokens and no code ----- */
$code  = $_GET['code']  ?? null;
$state = $_GET['state'] ?? null;

$accessToken = get_cookie('at');      // stored after PRG
$idToken     = get_cookie('idt');     // optional, stored after PRG

if (!$accessToken && !$code) {
  $st=rand_b64(16); $no=rand_b64(16); $ver=rand_b64(32);
  $chal=rtrim(strtr(base64_encode(hash('sha256',$ver,true)),'+/','-_'),'=');
  set_cookie('oidc_state',$st); set_cookie('oidc_nonce',$no); set_cookie('oidc_verif',$ver);
  $qs=http_build_query([
    'response_type'=>'code','client_id'=>$clientId,'redirect_uri'=>$redirectUri,
    'scope'=>'openid profile email','state'=>$st,'nonce'=>$no,
    'code_challenge'=>$chal,'code_challenge_method'=>'S256',
  ]);
  header('Location: '.$authEP.'?'.$qs); exit;
}

/** ----- Step 2: callback → exchange code; PRG to clean URL ----- */
if (!$accessToken && $code) {
  $stc=get_cookie('oidc_state'); $ver=get_cookie('oidc_verif');
  if(!$stc || !$ver || !hash_equals($stc,(string)$state)) fail(400,'Invalid or missing state');
  del_cookie('oidc_state'); del_cookie('oidc_verif'); del_cookie('oidc_nonce');

  $post=['grant_type'=>'authorization_code','code'=>$code,'redirect_uri'=>$redirectUri,'client_id'=>$clientId,'code_verifier'=>$ver];
  if(strlen((string)$clientSecret)>0) $post['client_secret']=$clientSecret;

  $tok=http_post_urlenc($tokenEP,$post,[], $verifyPeer,$verifyHost);
  $accessToken = $tok['access_token'] ?? null;
  $idToken     = $tok['id_token']     ?? null;
  if(!$accessToken) fail(500,'No access_token from token endpoint');

  // keep tokens briefly and redirect to clean URL (PRG)
  set_cookie('at',  $accessToken, 600);
  if ($idToken) set_cookie('idt', $idToken, 600);
  header('Location: '.$redirectUri); exit;
}

/** ----- Step 3: we have an access token → fetch userinfo ----- */
if (!$accessToken) fail(401,'Missing access token (login was not completed)');

$ui = $userEP ? http_get_json($userEP,['Authorization: Bearer '.$accessToken], $verifyPeer,$verifyHost) : [];
$email      = $ui['email']       ?? '';
$givenName  = $ui['given_name']  ?? '';
$familyName = $ui['family_name'] ?? '';
$name       = $ui['name']        ?? '';
$sub        = $ui['sub']         ?? (jwt_sub($idToken) ?? jwt_sub($accessToken));

if(!$sub){
  fail(500,"Could not determine user 'sub'. Ensure standard OIDC claims are returned.");
}
if(!$email && $name){ // best-effort for UI
  $parts=preg_split('/\s+/', $name,2); $givenName=$givenName ?: ($parts[0]??''); $familyName=$familyName ?: ($parts[1]??'');
}

/** ----- Helpers: PDF + upload ----- */
function make_pdf(array $d):string{
  $f=htmlspecialchars($d['first']??'',ENT_QUOTES,'UTF-8');
  $l=htmlspecialchars($d['last']??'', ENT_QUOTES,'UTF-8');
  $e=htmlspecialchars($d['email']??'',ENT_QUOTES,'UTF-8');
  $now=date('Y-m-d H:i:s');
  $html=<<<HTML
<!doctype html><html><head><meta charset="utf-8"><style>
body{font-family:DejaVu Sans,Arial,sans-serif;margin:32px}
h1{font-size:20px}.box{border:1px solid #999;padding:16px;border-radius:8px}
.row{margin:8px 0}.lbl{font-weight:700;width:140px;display:inline-block}
.muted{color:#666;font-size:12px;margin-top:20px}
</style></head><body>
<h1>Profile Submission</h1>
<div class="box">
  <div class="row"><span class="lbl">First name:</span> $f</div>
  <div class="row"><span class="lbl">Last name:</span> $l</div>
  <div class="row"><span class="lbl">Email:</span> $e</div>
  <div class="row"><span class="lbl">User ID (sub):</span> <!-- sub will be used in path --></div>
</div>
<p class="muted">Generated at $now</p>
</body></html>
HTML;
  $opts=new Options(); $opts->set('isRemoteEnabled',false);
  $pdf=new Dompdf($opts); $pdf->loadHtml($html); $pdf->setPaper('A4','portrait'); $pdf->render();
  return $pdf->output();
}

/** Per spec: always /auth/realms/{TENANT_NAME}/mpower/v1/users/{SUB}/media */
function chat_url(string $hostBase,string $tenant,string $sub):string{
  return rtrim($hostBase,'/').'/auth/realms/'.rawurlencode($tenant).'/mpower/v1/users/'.rawurlencode($sub).'/media';
}

function upload_pdf(string $url,string $accessToken,string $bytes,string $filename,string $message,bool $vp,bool $vh):array{
  $tmp=tmpfile(); $path=stream_get_meta_data($tmp)['uri']; file_put_contents($path,$bytes);
  $cfile=new CURLFile($path,'application/pdf',$filename);
  $resp = http_post_form(
    $url,
    ['attachment'=>$cfile,'message'=>$message],
    ['Accept: application/json','Authorization: Bearer '.$accessToken],
    $vp,$vh
  );
  fclose($tmp);
  return $resp;
}

/** ----- Handle POST (Send as PDF) ----- */
if ($_SERVER['REQUEST_METHOD']==='POST') {
  // CSRF
  $cookieCsrf = get_cookie('csrf') ?? '';
  $postedCsrf = $_POST['csrf'] ?? '';
  if (!$cookieCsrf || !$postedCsrf || !hash_equals($cookieCsrf, (string)$postedCsrf)) {
    fail(400,'Bad Request (CSRF)');
  }

  if (isset($_POST['send_pdf'])) {
    $first = trim($_POST['first_name'] ?? '') ?: $givenName;
    $last  = trim($_POST['last_name']  ?? '') ?: $familyName;
    $mail  = trim($_POST['email']      ?? '') ?: $email;
    $msg   = trim($_POST['message']    ?? '');
    if ($msg === '') $msg = 'Form PDF';

    // USER_ID = sub (not email)
    $endpoint = chat_url($hostBase, $tenant, $sub);

    $pdfBytes = make_pdf(['first'=>$first,'last'=>$last,'email'=>$mail]);
    $resp = upload_pdf($endpoint, $accessToken, $pdfBytes, 'profile-'.date('Ymd-His').'.pdf', $msg, $verifyPeer, $verifyHost);

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

/** ----- Render UI ----- */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC → Prefilled Form → Send as PDF (USER_ID = sub)</title>
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

    <label for="email">Email</label>
    <input id="email" type="email" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>">

    <label for="message">Optional message</label>
    <textarea id="message" name="message" rows="3" placeholder="(leave empty if not needed)">Form PDF</textarea>

    <button type="submit" name="send_pdf">Send as PDF</button>
  </form>
</body>
</html>
