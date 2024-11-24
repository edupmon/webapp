<?php
session_start();
require 'db.php';

define('SESSION_TIMEOUT', 1800); // Timeout in seconds (30 minutes)

// Check session timeout
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
    // Session timed out, destroy session and redirect to login
    session_unset();
    session_destroy();
    header("Location: login.php?timeout=1");
    exit;
}
$_SESSION['last_activity'] = time(); // Update last activity timestamp

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $conn = getDatabaseConnection();

    // Check account lock status
    $stmt = $conn->prepare("SELECT failed_attempts, locked_until FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($failedAttempts, $lockedUntil);
    $stmt->fetch();
    $stmt->close();

    if ($lockedUntil && strtotime($lockedUntil) > time()) {
        $error = 'Usuário bloqueado. Tente novamente mais tarde';
    } else {
        // Validate username and password
        $stmt = $conn->prepare("SELECT username, user_password, user_admin FROM users WHERE username = ? AND enabled = 1");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 1) {
            $stmt->bind_result($dbUsername, $dbPassword, $dbUserAdmin);
            $stmt->fetch();

            if (password_verify($password, $dbPassword)) {
                // Reset failed attempts and update last login
                $resetStmt = $conn->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE username = ?");
                $resetStmt->bind_param("s", $username);
                $resetStmt->execute();
                $resetStmt->close();

                // Secure session
                session_regenerate_id(true);
                $_SESSION['username'] = $dbUsername;
                $_SESSION['admin'] = $dbUserAdmin;
                $_SESSION['last_activity'] = time(); // Set last activity timestamp

                // Redirect to dashboard
                header("Location: dashboard.php");
                exit;
            } else {
                // Increment failed attempts
                $updateStmt = $conn->prepare("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?");
                $updateStmt->bind_param("s", $username);
                $updateStmt->execute();

                // Lock account if attempts exceed limit
                if ($failedAttempts + 1 >= 5) {
                    $lockStmt = $conn->prepare("UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE username = ?");
                    $lockStmt->bind_param("s", $username);
                    $lockStmt->execute();
                    $lockStmt->close();
                    $error = 'Muitas tentativas de acesso. Usuário bloqueado por 15 minutos.';
                }
                $updateStmt->close();

                $error = 'Usuário ou Senha Inválidos.';
            }
        } else {
            $error = 'Usuário ou Senha Inválidos.';
        }

        $stmt->close();
    }

    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acesso</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h1>WebApp</h1>
        <?php if (isset($_GET['timeout']) && $_GET['timeout'] == 1): ?>
            <div class="error">Sua sessão expirou. Por favor, faça login novamente.</div>
        <?php elseif ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form action="" method="post">
            <input type="text" name="username" placeholder="Usuário" required>
            <input type="password" name="password" placeholder="Senha" required>
            <button type="submit">Acessar</button>
        </form>
    </div>
</body>
</html>
