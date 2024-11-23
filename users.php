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
$isAdmin = htmlspecialchars($_SESSION['admin']) === '1';

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
        $submittedAdmin = isset($_POST['admin']) ? 1 : 0;
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
            $stmt = $conn->prepare("INSERT INTO users (username, user_password, user_admin, enabled, created_by) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("ssiis", $submittedUsername, $hashedPassword, $submittedAdmin, $submittedEnabled, $_SESSION['username']);
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
                    $query .= "user_password = ?, ";
                    $params[] = $hashedPassword;
                    $types .= "s";
                }
                
                if ($isAdmin) {
                    $query .= "user_admin = ?, ";
                    $params[] = $submittedAdmin;
                    $types .= "i";
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
    $stmt = $conn->prepare("SELECT username, user_password, user_admin, enabled FROM users");
} else {
    // Non-admin: Retrieve only the logged-in user
    $stmt = $conn->prepare("SELECT username, user_password FROM users WHERE username = ?");
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
    // Reusable validation function
    function validateField(field, value) {
        const validators = {
            password: /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/,
            username: /^[a-z]{4,12}$/,
        };

        if (!validators[field]) {
            console.warn(`No validator defined for field: ${field}`);
            return true; // Default to valid if no validator is defined
        }

        return validators[field].test(value);
    }

    // Reusable function to submit a form via AJAX
    function submitFormAjax(form, url, successMessage, errorMessage) {
        const formData = form.serialize(); // Serialize form data

        $.ajax({
            url: url,
            type: 'POST',
            data: formData,
            dataType: 'json',
            success: function (response) {
                if (response.success) {
                    alert(successMessage);
                    form[0].reset(); // Clear form fields
                    location.reload(); // Reload the page to reflect changes
                } else {
                    alert(response.error || errorMessage);
                }
            },
            error: function (xhr, status, error) {
                console.error('Erro ao processar solicitação:', status, error);
                alert('Erro na comunicação com o servidor.');
            }
        });
    }

    // Handle form submission via AJAX
    $(document).on('submit', '.user-form, .add-user-form', function (event) {
        event.preventDefault(); // Prevent the default form submission

        const form = $(this);
        const isAddUser = form.hasClass('add-user-form'); // Determine the form type
        const field = isAddUser ? 'username' : 'password';
        const input = form.find(`input[name="${field}"]`);
        const value = input.val();

        // Client-side validation
        if (value && !validateField(field, value)) {
            const errorMessage = isAddUser
                ? 'O nome de usuário deve conter apenas letras minúsculas (a-z), sem espaços, com 4 a 12 caracteres.'
                : 'A senha deve ter pelo menos 8 caracteres, incluindo um número, uma letra maiúscula e um caractere especial.';
            alert(errorMessage);
            return;
        }

        // Submit form via AJAX
        const successMessage = isAddUser
            ? 'Usuário adicionado com sucesso!'
            : 'Alterações efetuadas com sucesso!';
        const errorMessage = isAddUser
            ? 'Erro ao adicionar usuário.'
            : 'Erro ao gravar alterações.';

        submitFormAjax(form, 'users.php', successMessage, errorMessage);
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
                        <?php if ($isAdmin): ?>
                        	<th style="text-align: center; vertical-align: middle;">Administrador</th>
                        <?php endif; ?>
                        <?php if ($isAdmin): ?>
                        	<th style="text-align: center; vertical-align: middle;">Habilitado</th>
                        <?php endif; ?>
                        <th style="text-align: center; vertical-align: middle;">Ações</th>
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
                                <?php if ($isAdmin): ?>
                                	<td style="text-align: center; vertical-align: middle;">
                                        <input type="checkbox" name="admin" value="1" <?php echo $user['user_admin'] ? 'checked' : ''; ?>>
                               		</td>
                                <?php endif; ?>
                                <!-- Enabled -->
                                <?php if ($isAdmin): ?>
                                	<td style="text-align: center; vertical-align: middle;">
                                        <input type="checkbox" name="enabled" value="1" <?php echo $user['enabled'] ? 'checked' : ''; ?>>
                               		</td>
                                <?php endif; ?>
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
                        <th style="text-align: center; vertical-align: middle;">Administrador</th>
                        <th style="text-align: center; vertical-align: middle;">Habilitado</th>
                        <th style="text-align: center; vertical-align: middle;">Ações</th>
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
                                <input type="checkbox" name="admin" value="1">
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

