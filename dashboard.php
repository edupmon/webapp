<?php
session_start();

define('SESSION_TIMEOUT', 1800); // 30 minutes

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

$username = htmlspecialchars($_SESSION['username']);

// Get the current page filename
$page = isset($_GET['page']) ? $_GET['page'] : 'home';
$allowed_pages = ['home', 'users']; // List of allowed pages for security
if (!in_array($page, $allowed_pages)) {
    $page = 'home'; // Default to 'home' if page is not allowed
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        /* Sidebar styles */
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            width: 250px;
            height: 100%;
            background-color: #dce7f9; /* Lighter blue */
            color: #2a4f96; /* Darker text color for contrast */
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: transform 0.3s ease;
        }
        
        .sidebar.collapsed {
            transform: translateX(-100%);
        }
        
        .sidebar-header {
            padding: 20px;
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            background-color: #b0c7e5; /* Slightly darker blue for header contrast */
            color: #2a4f96;
        }
        
        .menu {
            flex-grow: 1;
            padding: 20px;
        }
        
        .menu a {
            display: block;
            color: #2a4f96;
            text-decoration: none;
            margin: 10px 0;
            padding: 10px;
            border-radius: 4px;
            transition: background-color 0.3s ease;
        }
        
        .menu a.active,
        .submenu a.active {
            background-color: #2a4f96; /* Highlight color */
            color: #fff; /* Text color */
            font-weight: bold;
        }
        
        .menu a:hover {
            background-color: #b0c7e5; /* Match header color on hover */
        }
        
        .logout {
            margin: 20px;
        }
        
        .logout button {
            width: 100%;
        }
        
        /* Submenu styles */
        .menu-item {
            position: relative;
        }
        
        .submenu {
            list-style: none;
            padding: 0;
            margin: 0;
            display: none; /* Hidden by default */
        }
        
        .submenu li {
            padding-left: 20px; /* Indent for subitems */
        }
        
        .submenu a {
            color: #2a4f96;
            text-decoration: none;
            display: block;
            padding: 5px 10px;
            border-radius: 4px;
            transition: background-color 0.3s ease;
        }
        
        .submenu a:hover {
            background-color: #b0c7e5; /* Same hover color as menu items */
        }
        
        /* Visible submenu */
        .submenu.active {
            display: block; /* Show submenu */
        }

        /* Main content styles */
        .main {
            margin-left: 250px;
            padding: 30px 20px;
            margin-top: 20px;
            transition: margin-left 0.3s ease;
        }

        .sidebar.collapsed ~ .main {
            margin-left: 0;
        }

        /* Toggle button styles */
        .toggle-btn {
            position: absolute;
            top: 10px;
            left: 10px;
            background-color: #2a4f96;
            color: #fff;
            border: none;
            padding: 10px;
            cursor: pointer;
            border-radius: 4px;
        }
        
        /* Responsive adjustments */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
        
            .sidebar.collapsed {
                transform: translateX(0);
            }
        
            .main {
                margin-left: 0;
            }
        
            .sidebar.collapsed ~ .main {
                margin-left: 250px;
            }
        }
    </style>
    <script>
        // Toggle sidebar
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('collapsed');
        }

        // Toggle submenu with auto-collapse for others
        function toggleSubmenu(submenuId) {
            const allSubmenus = document.querySelectorAll('.submenu');
            const submenu = document.getElementById(submenuId);
            const toggleLink = submenu.previousElementSibling; // The parent menu item

            // Collapse all other submenus
            allSubmenus.forEach((otherSubmenu) => {
                if (otherSubmenu !== submenu) {
                    otherSubmenu.classList.remove('active');
                    const parentLink = otherSubmenu.previousElementSibling;
                    if (parentLink) {
                        parentLink.setAttribute('aria-expanded', 'false');
                    }
                }
            });

            // Toggle the selected submenu
            submenu.classList.toggle('active');
            const isExpanded = submenu.classList.contains('active');
            toggleLink.setAttribute('aria-expanded', isExpanded);
        }
    </script>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <?php echo $username; ?>
        </div>
        <div class="menu">
            <!-- New "Início" menu item -->
            <div class="menu-item">
                <a href="dashboard.php?page=home" class="<?php echo $page == 'home' ? 'active' : ''; ?>">
                	Início
                </a>
            </div>
            <div class="menu-item">
                <a href="#" onclick="toggleSubmenu('admin-submenu')"
                   aria-expanded="<?php echo in_array($page, ['users']) ? 'true' : 'false'; ?>"
                   aria-controls="admin-submenu">
                	Administração
                </a>
                <ul id="admin-submenu" class="submenu <?php echo in_array($page, ['users']) ? 'active' : ''; ?>">
                    <li>
                        <a href="dashboard.php?page=users" class="<?php echo $page == 'users' ? 'active' : ''; ?>">
                        	Usuários
                        </a>
                    </li>
                </ul>
            </div>
        </div>
        <div class="logout">
            <form action="logout.php" method="post">
                <button type="submit">Sair</button>
            </form>
        </div>
    </div>
    <!-- Main Content -->
    <button class="toggle-btn" onclick="toggleSidebar()">☰</button>
    <div class="main">
        <?php include $page . '.php'; ?>
    </div>
</body>
</html>
