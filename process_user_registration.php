
<?php

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    require "db_connect_mysqli.php";

    if ($_SERVER["REQUEST_METHOD"] !== "POST") {
        exit("Error: This page must be opened by submitting the registration form.");
    }

    $name = trim($_POST["name"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($name === "" || $email === "" || $password === "") {
        exit("Error: All fields are required.");
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        exit("Error: Please enter a valid email address.");
    }

    if (strlen($password) < 6) {
        exit("Error: Password must contain at least 6 characters.");
    }

    $check_stmt = $conn->prepare(
        "SELECT id FROM users WHERE email = ?"
    );

    $check_stmt->bind_param("s", $email);
    $check_stmt->execute();
    $check_stmt->store_result();

    if ($check_stmt->num_rows > 0) {
        $check_stmt->close();
        exit("Error: This email is already registered.");
    }

    $check_stmt->close();

    $hashed_password = password_hash(
        $password,
        PASSWORD_DEFAULT
    );

    $stmt = $conn->prepare(
        "INSERT INTO users (name, email, password)
         VALUES (?, ?, ?)"
    );

    $stmt->bind_param("sss", $name, $email, $hashed_password);
    $stmt->execute();

    echo "<h2>Registration Successful!</h2>";
    echo "<p>Your account has been registered securely.</p>";
    echo '<a href="register_user.html">Register Another User</a>';

    $stmt->close();
    $conn->close();

} catch (Throwable $e) {
    http_response_code(500);
    echo "<h3>Registration error</h3>";
    echo "<pre>" .
         htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') .
         "</pre>";
}
?>
