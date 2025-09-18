<?php
declare(strict_types=1);
session_start();

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/config.php';

use Jumbojett\OpenIDConnectClient;

// --- Simple CSRF helper ---
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

// --- Logout ---
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    header('Location: ' . OIDC_LOGOUT_REDIRECT);
    exit;
}

// --- Handle form submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $firstName = $_POST['first_name'] ?? '';
    $lastName  = $_POST['last_name'] ?? '';
    $email     = $_POST['email'] ?? '';
    echo "<h2>Saved values</h2><pre>" . htmlspecialchars(print_r([
        'first_name' => $firstName,
        'last_name'  => $lastName,
        'email'      => $email,
    ], true), ENT_QUOTES, 'UTF-8') . "</pre>";
    echo '<p><a href="index.php">Back</a></p>';
    exit;
}

// --- Authenticate via OIDC ---
try {
    $oidc = new OpenIDConnectClient(
        OIDC_PROVIDER_URL,
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET
    );

    $oidc->setRedirectURL(OIDC_REDIRECT_URI);
    foreach (OIDC_SCOPES as $scope) {
        $oidc->addScope($scope);
    }

    $oidc->authenticate();

    $idTokenClaims = $oidc->getVerifiedClaims();
    $userinfo      = $oidc->requestUserInfo();
    $claims        = array_merge((array)$idTokenClaims, (array)$userinfo);

    $email     = $claims['email']       ?? '';
    $givenName = $claims['given_name']  ?? '';
    $familyName= $claims['family_name'] ?? '';
    $name      = $claims['name']        ?? '';

    if (!$givenName && !$familyName && $name) {
        $parts = explode(' ', $name, 2);
        $givenName = $parts[0];
        $familyName = $parts[1] ?? '';
    }

} catch (Exception $e) {
    http_response_code(500);
    echo "<h2>Login error</h2><pre>" . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
    echo '<p><a href="?action=logout">Retry</a></p>';
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC Form Demo</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    form { max-width: 500px; display: grid; gap: 1rem; }
    input { padding: 0.5rem; border: 1px solid #ccc; border-radius: 6px; }
    button { padding: 0.6rem 1rem; border: none; border-radius: 6px; background: #0070f3; color: white; cursor: pointer; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  </style>
</head>
<body>
  <h1>Welcome <?= htmlspecialchars($givenName ?: 'User', ENT_QUOTES, 'UTF-8'); ?> 👋</h1>
  <a href="?action=logout"><button>Logout</button></a>

  <h2>Update your profile</h2>
  <form method="post">
    <?= csrf_input(); ?>
    <div class="row">
      <div>
        <label for="first_name">First Name</label>
        <input id="first_name" name="first_name" value="<?= htmlspecialchars($givenName, ENT_QUOTES, 'UTF-8'); ?>">
      </div>
      <div>
        <label for="last_name">Last Name</label>
        <input id="last_name" name="last_name" value="<?= htmlspecialchars($familyName, ENT_QUOTES, 'UTF-8'); ?>">
      </div>
    </div>
    <label for="email">Email</label>
    <input id="email" type="email" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>">
    <button type="submit">Save</button>
  </form>

  <details>
    <summary>Debug: raw claims</summary>
    <pre><?= htmlspecialchars(print_r($claims, true), ENT_QUOTES, 'UTF-8'); ?></pre>
  </details>
</body>
</html>
