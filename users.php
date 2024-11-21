<?php
// Start session only if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Define session timeout constant if not already defined
if (!defined('SESSION_TIMEOUT')) {
    define('SESSION_TIMEOUT', 1800); // 30 minutes
}

// Check session timeout
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
    session_unset();
    session_destroy();
    header("Location: login.php?timeout=1");
    exit;
}
$_SESSION['last_activity'] = time(); // Update last activity timestamp

// Check if user is logged in
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

require 'db.php'; // Database connection
$username = htmlspecialchars($_SESSION['username']);
$isAdmin = $username === 'admin';

// Helper function to validate usernames
function validateUsername($username) {
    $usernameRegex = '/^[a-z]{4,12}$/';
    if (empty($username)) {
        throw new Exception('O nome de usuário é obrigatório.');
    }
    if (!preg_match($usernameRegex, $username)) {
        throw new Exception('Nome de usuário inválido. O nome de usuário deve conter apenas letras minúsculas (a-z), sem espaços, com 4 a 12 caracteres.');
    }
}

// Helper function to validate passwords
function validatePassword($password) {
    $passwordRegex = '/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/';
    if (empty($password)) {
        throw new Exception('A senha é obrigatória.');
    }
    if (!preg_match($passwordRegex, $password)) {
        throw new Exception('Senha inválida. A senha deve conter pelo menos 8 caracteres, incluindo um número, uma letra maiúscula e um caractere especial.');
    }
}

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json'); // Ensure JSON response
    $response = ['success' => false]; // Default response

    try {
        $submittedUsername = $_POST['username'] ?? null;
        $submittedPassword = $_POST['password'] ?? null;
        $submittedEnabled = isset($_POST['enabled']) ? 1 : 0;
        $isNewUser = isset($_POST['new_user']) ? true : false;

        // Validate the username
        validateUsername($submittedUsername);

        $conn = getDatabaseConnection();

        if ($isNewUser && $isAdmin) {
            // Validate password for new users
            validatePassword($submittedPassword);

            // Add new user
            $hashedPassword = password_hash($submittedPassword, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO users (username, password, enabled, created_by) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssis", $submittedUsername, $hashedPassword, $submittedEnabled, $_SESSION['username']);
            if (!$stmt->execute()) {
                throw new Exception('Erro ao adicionar o usuário.');
            }
            $stmt->close();
            $response['success'] = true;
        } else {
            // Validate password for updates (if provided)
            if (!empty($submittedPassword)) {
                validatePassword($submittedPassword);
            }

            // Update user
            if ($isAdmin || $submittedUsername === $username) {
                $query = "UPDATE users SET ";
                $params = [];
                $types = "";

                if (!empty($submittedPassword)) {
                    $hashedPassword = password_hash($submittedPassword, PASSWORD_DEFAULT);
                    $query .= "password = ?, ";
                    $params[] = $hashedPassword;
                    $types .= "s";
                }

                if ($isAdmin) {
                    $query .= "enabled = ?, ";
                    $params[] = $submittedEnabled;
                    $types .= "i";
                }

                $query = rtrim($query, ", ") . " WHERE username = ?";
                $params[] = $submittedUsername;
                $types .= "s";

                $stmt = $conn->prepare($query);
                $stmt->bind_param($types, ...$params);
                if (!$stmt->execute()) {
                    throw new Exception('Erro ao atualizar o usuário.');
                }
                $stmt->close();
                $response['success'] = true;
            }
        }
        $conn->close();
    } catch (Exception $e) {
        $response['error'] = $e->getMessage();
        error_log('Erro: ' . $e->getMessage());
    }

    echo json_encode($response);
    exit;
}

// Fetch users data
$conn = getDatabaseConnection();
if ($isAdmin) {
    // Admin: Retrieve all users
    $stmt = $conn->prepare("SELECT username, password, enabled FROM users");
} else {
    // Non-admin: Retrieve only the logged-in user
    $stmt = $conn->prepare("SELECT username, password, enabled FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
}
$stmt->execute();
$result = $stmt->get_result();
$users = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();
$conn->close();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Usuários</title>
    <link rel="stylesheet" href="styles.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        function validatePassword(password) {
            const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
            return passwordRegex.test(password);
        }
        function validateUsername(username) {
            const usernameRegex = /^[a-z]{4,12}$/;
            return usernameRegex.test(username);
        }
    
        // Handle form submission via AJAX
        $(document).on('submit', '.user-form', function(event) {
            event.preventDefault(); // Prevent the default form submission
    
            const form = $(this);
            const passwordInput = form.find('input[name="password"]');
            const password = passwordInput.val();
    
            // Client-side validation
            if (password && !validatePassword(password)) {
                alert('A senha deve ter pelo menos 8 caracteres, incluindo um número, uma letra maiúscula e um caractere especial.');
                return;
            }
    
            const formData = form.serialize(); // Serialize form data
    
            $.ajax({
                url: 'users.php',
                type: 'POST',
                data: formData,
                dataType: 'json',
                success: function(response) {
                    if (response.success) {
                        alert('Alterações efetuadas com sucesso!');
                        form[0].reset(); // Clear form fields
                        location.reload(); // Reload the page to reflect changes
                    } else {
                        alert(response.error || 'Erro ao gravar alterações.');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Erro ao processar solicitação:', status, error);
                    alert('Erro na comunicação com o servidor.');
                }
            });
        });
    
        // Handle "Adicionar Novo Usuário" form submission via AJAX
        $(document).on('submit', '.add-user-form', function(event) {
            event.preventDefault(); // Prevent the default form submission
    
            const form = $(this);
            const usernameInput = form.find('input[name="username"]');
            const username = usernameInput.val();
            
            // Client-side username validation
            if (!validateUsername(username)) {
                alert('O nome de usuário deve conter apenas letras minúsculas (a-z), sem espaços, com 4 a 12 caracteres.');
                return;
            }            
            
            const formData = form.serialize(); // Serialize form data
    
            $.ajax({
                url: 'users.php',
                type: 'POST',
                data: formData,
                dataType: 'json',
                success: function(response) {
                    if (response.success) {
                        alert('Usuário adicionado com sucesso!');
                        form[0].reset(); // Clear the form
                        location.reload(); // Reload the page to show the new user
                    } else {
                        alert(response.error || 'Erro ao adicionar usuário.');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Erro ao processar solicitação:', status, error);
                    alert('Erro na comunicação com o servidor.');
                }
            });
        });
    </script>
</head>
<body>
    <div class="main">
        <h1>Usuários</h1>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Usuário</th>
                        <th>Senha</th>
                        <th>Habilitado</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <form class="user-form">
                                <!-- Username -->
                                <td style="text-align: left; vertical-align: middle;">
                                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                    <?php echo htmlspecialchars($user['username']); ?>
                                </td>
                                <!-- Password (Plain text input) -->
                                <td style="text-align: left; vertical-align: middle;">
                                    <?php if ($isAdmin || $user['username'] === $username): ?>
                                        <input type="text" name="password" placeholder="Nova Senha">
                                    <?php else: ?>
                                        <input type="text" placeholder="********" readonly>
                                    <?php endif; ?>
                                </td>
                                <!-- Enabled -->
                                <td style="text-align: center; vertical-align: middle;">
                                    <?php if ($isAdmin): ?>
                                        <input type="checkbox" name="enabled" value="1" <?php echo $user['enabled'] ? 'checked' : ''; ?>>
                                    <?php else: ?>
                                        <input type="checkbox" <?php echo $user['enabled'] ? 'checked' : ''; ?> disabled>
                                    <?php endif; ?>
                                </td>
                                <!-- Save Button -->
                                <td style="text-align: center; vertical-align: middle;">
                                    <button type="submit">Atualizar</button>
                                </td>
                            </form>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <!-- Show "Adicionar Novo Usuário" only for admin -->
        <?php if ($isAdmin): ?>
        <div class="add-user-container">
            <h2>Adicionar Novo Usuário</h2>
            <table>
                <thead>
                    <tr>
                        <th>Usuário</th>
                        <th>Senha</th>
                        <th>Habilitado</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <form class="add-user-form">
                            <td style="text-align: left; vertical-align: middle;">
                                <input type="text" name="username" placeholder="Novo Usuário" required>
                            </td>
                            <td style="text-align: left; vertical-align: middle;">
                                <input type="text" name="password" placeholder="Senha" required>
                            </td>
                            <td style="text-align: center; vertical-align: middle;">
                                <input type="checkbox" name="enabled" value="1">
                            </td>
                            <td style="text-align: center; vertical-align: middle;">
                                <input type="hidden" name="new_user" value="1">
                                <button type="submit">Adicionar</button>
                            </td>
                        </form>
                    </tr>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>

