<?php
// 1. CORS Headers and Content Type
// Replace 'http://vrhere.in' with your actual frontend URL (if running on a different port/domain in XAMPP)
header("Access-Control-Allow-Origin: http://vrhere.in"); 
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// 2. Include the secure database connection
// The '..' navigates up one level from 'api/' to 'vr_here/', then back down into 'api/'
require_once 'db_connect.php'; 

// Function to send a JSON response
function sendResponse($success, $message, $data = []) {
    $response = ['success' => $success, 'message' => $message];
    if (!empty($data)) {
        $response['data'] = $data;
    }
    echo json_encode($response);
    exit;
}

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Set 405 Method Not Allowed header
    header('HTTP/1.1 405 Method Not Allowed');
    sendResponse(false, "Invalid request method.");
}

// Get the posted data (JSON format from React)
$data = json_decode(file_get_contents("php://input"), true);

if (!isset($data['email']) || !isset($data['password'])) {
    sendResponse(false, "Missing email or password.");
}

$email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
$password = $data['password'];

// Connect to the database
$conn = connectDB(); 

if (!$conn) {
    sendResponse(false, "System error: Could not connect to database.");
}

// 3. Prepare and execute the query
// We select the ID, HASHED password (from your 'password' column), and the user's role.
$stmt = $conn->prepare("SELECT id, password, role FROM users WHERE email = ?"); 
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    $stored_hash = $user['password']; // Retrieve the hash from the 'password' column
    $role = $user['role'];
    
    // 4. Secure Password Verification
    // Checks the plain text password against the hash retrieved from the database.
    if (password_verify($password, $stored_hash)) {
        
        // SUCCESS: Authentication passed.
        
        // Start a session
        session_start();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_role'] = $role;
        $_SESSION['user_name'] = $user['name']; // Assuming you'll query name later or add it to the SELECT statement

        // Prepare the redirect path based on the role
        $redirect_role = ($role === 'customer') ? 'client' : $role;
        
        sendResponse(true, "Login successful.", [
            'role' => $role,
            'user_id' => $user['id'],
            'redirect_path' => '/' . $redirect_role // e.g., /admin, /employee, /client
        ]);
        
    } else {
        // Password did not match the hash
        sendResponse(false, "Invalid email or password.");
    }
} else {
    // No user found with that email
    sendResponse(false, "Invalid email or password.");
}

$stmt->close();
$conn->close();

?>