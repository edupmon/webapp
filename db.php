<?php
// Database connection function
function getDatabaseConnection() {
    // Load the configuration from the .ini file
    $config = parse_ini_file('db.ini', true);

    if (!$config || !isset($config['database'])) {
        error_log('Database configuration file is missing or invalid.');
        die('Database configuration error.');
    }

    // Database connection parameters
    $dbConfig = $config['database'];
    $servername = $dbConfig['servername'];
    $username = $dbConfig['username'];
    $password = $dbConfig['password'];
    $dbname = $dbConfig['dbname'];
    $port = $dbConfig['port'];

    // Create connection
    $conn = new mysqli($servername, $username, $password, $dbname, $port);

    // Check connection
    if ($conn->connect_error) {
        error_log('Database connection failed: ' . $conn->connect_error); // Log error
        die('Connection failed. Please try again later.'); // Generic message for security
    }

    // Set the character set to UTF-8
    if (!$conn->set_charset("utf8mb4")) {
        error_log('Error loading character set utf8mb4: ' . $conn->error); // Log error
        die('Failed to set database character set.');
    }

    return $conn;
}
?>
