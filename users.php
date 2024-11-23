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

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json'); // Ensure JSON response
    $response = ['success' => false]; // Default response

    try {
        $submittedUsername = $_POST['username'] ?? null;
        $submittedPassword = $_POST['password'] ?? null;
        $submittedAdmin = isset($_POST['admin']) ? 1 : 0;
        $submittedEnabled = isset($_POST['enabled']) ? 1 : 0;
        $submittedAddUser = isset($_POST['add_user']) ? true : false;
        $submittedDeleteUser = isset($_POST['delete_user']) ? true : false;

        // Validate the username
        validateUsername($submittedUsername);

        $conn = getDatabaseConnection();

        if ($submittedAddUser && $isAdmin) {
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
        } else if ($submittedDeleteUser && $isAdmin) {
        	$submittedUsername = $_POST['username'] ?? null;
        	if (empty($submittedUsername)) {
            	throw new Exception('O nome de usuário é obrigatório para exclusão.');
        	}
        	
        	// Prevent deleting the currently logged-in user
        	if ($submittedUsername === $username) {
        	    throw new Exception('Você não pode excluir seu próprio usuário.');
        	}
        	
        	// Validate if the submitted username exists in the list of users
        	$userExists = false;
        	foreach ($users as $user) {
        	    if ($user['username'] === $submittedUsername) {
        	        $userExists = true;
        	        break;
        	    }
        	}
        	
        	if (!$userExists) {
        	    throw new Exception('O usuário especificado não existe.');
        	}
        	
        	// Proceed to delete the user
        	$stmt = $conn->prepare("DELETE FROM users WHERE username = ?");
        	$stmt->bind_param("s", $submittedUsername);
        	if (!$stmt->execute()) {
            	throw new Exception('Erro ao excluir o usuário.');
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
        // Handle form submission via AJAX
        $(document).on('submit', '.user-form, .add-user-form, .delete-user-form', function(event) {
            event.preventDefault();

            const form = $(this);
            const formData = form.serialize(); // Serialize form data
            
            // Submit form via AJAX
            $.ajax({
                url: 'users.php',
                type: 'POST',
                data: formData,
                dataType: 'json',
                success: function(response) {
                    if (response.success) {
                        alert('Operação realizada com sucesso!');
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
    </script>
</head>
<body>
    <div class="main">
        <h1>Usuários</h1>
        
        <!-- Add New User (Admin Only) -->
        <?php if ($isAdmin): ?>
            <div class="add-user-container">
                <h2>Adicionar Novo Usuário</h2>
                <form class="add-user-form">
                    <table>
                        <thead>
                            <tr>
                                <th>Usuário</th>
                                <th>Senha</th>
                                <th style="text-align:center;">Administrador</th>
                                <th style="text-align:center;">Habilitado</th>
                                <th style="text-align:center;">Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>
                                    <input type="text" name="username" placeholder="Novo Usuário" required>
                                </td>
                                <td>
                                    <input type="text" name="password" placeholder="Senha" required>
                                </td>
                                <td style="text-align:center;">
                                    <input type="checkbox" name="admin" value="1">
                                </td>
                                <td style="text-align:center;">
                                    <input type="checkbox" name="enabled" value="1">
                                </td>
                                <td style="text-align:center;">
                                    <input type="hidden" name="add_user" value="1">
                                    <button type="submit">Adicionar</button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </form>
            </div>
        <?php endif; ?>
        
        <!-- Delete User (Admin Only) -->
        <?php if ($isAdmin): ?>
            <div class="delete-user-container">
                <h2>Excluir Usuário</h2>
                <form class="delete-user-form">
                    <table>
                        <thead>
                            <tr>
                                <th>Usuário</th>
                                <th style="text-align:center;">Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>
                                    <input type="text" name="username" placeholder="Usuário" required>
                                </td>
                                <td style="text-align:center;">
                                    <input type="hidden" name="delete_user" value="1">
                                    <button type="submit">Excluir</button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </form>
            </div>
        <?php endif; ?>
        
        <!-- Existing Users -->
        <div class="user-container">
            <h2>Usuários Cadastrados</h2>
            <table>
                <thead>
                    <tr>
                        <th>Usuário</th>
                        <th>Senha</th>
                        <?php if ($isAdmin): ?>
                            <th style="text-align:center;">Administrador</th>
                            <th style="text-align:center;">Habilitado</th>
                        <?php endif; ?>
                        <th style="text-align:center;">Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <form class="user-form">
                                <td>
                                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                    <?php echo htmlspecialchars($user['username']); ?>
                                </td>
                                <td>
                                    <?php if ($isAdmin || $user['username'] === $username): ?>
                                        <input type="text" name="password" placeholder="Nova Senha">
                                    <?php else: ?>
                                        <input type="text" placeholder="********" readonly>
                                    <?php endif; ?>
                                </td>
                                <?php if ($isAdmin): ?>
                                    <td style="text-align:center;">
                                        <input type="checkbox" name="admin" value="1" <?php echo $user['user_admin'] ? 'checked' : ''; ?>>
                                    </td>
                                    <td style="text-align:center;">
                                        <input type="checkbox" name="enabled" value="1" <?php echo $user['enabled'] ? 'checked' : ''; ?>>
                                    </td>
                                <?php endif; ?>
                                <td style="text-align:center;">
                                    <button type="submit">Atualizar</button>
                                </td>
                            </form>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
