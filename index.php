<?php
session_start();
require_once "login.php";

//these functions originally included in a utilities.php file, but copy and pasted here to make sure no issues with format
function sanitize($data) {
    $data = trim($data);
    $data = stripslashes($data);
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

function displayError() {
    echo "An unexpected error occurred. Please try again later.";
    exit();
}



try {
    $conn = new mysqli($servername, $db_username, $db_password, $dbname);
    $conn->set_charset("utf8mb4");
} catch (mysqli_sql_exception $e) {
    displayError();
}

// If user already logged in, redirect to main page
if (isset($_SESSION['user_id'])) {
    if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
        $conn->close();
    }
    header("Location: main_page.php");
    exit();
}

// handling sign up here
if (isset($_POST['signup'])) {
    $name = sanitize($_POST['name']);
    $student_id = sanitize($_POST['student_id']);
    $email = sanitize($_POST['email']);
    $password = sanitize($_POST['password']);

    // if fields are empty let user know this should never happen due to client side validtion as long as user isnt sending request direct to server bypassing client
    if (empty($name) || empty($student_id) || empty($email) || empty($password)) {
        if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
            $conn->close();
        }
        echo "All fields are required.";
        exit();
    }

    // make sure that the student id is exactly 9 didgets long
    if (!preg_match('/^[0-9]{9}$/', $student_id)) {
        echo "Student ID must be exactly 9 digits.";
        if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
            $conn->close();
        }
        exit();
    }

    // use the default php email validator then also make sure that email is an sjsu email address
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/@sjsu\.edu$/', $email)) {
        echo "Email must be a valid sjsu.edu email.";
        if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
            $conn->close();
        }
        exit();
    }

    //make sure that the password is more than 6 characters long and that it has 1 uppercase letter, lowercase letter and number
    if (strlen($password) < 7 || !preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) ) {
        echo "Password must be more than 6 characters, and include at least one uppercase and one lowercase letter.";
        if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
            $conn->close();
        }
        exit();
    }

    //hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // check to see if there is a duplicate email or student id in database and error out / tell user if so
    $stmt = $conn->prepare("SELECT id FROM credentials WHERE email = ? OR student_id = ?");
    $stmt->bind_param("ss", $email, $student_id); // bind email and student id to statement
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) { // error out with non generic error if user already exists to let user know
        echo "Email or Student ID already exists.";
        exit();
    }
    $stmt->close();

    // prepare query to insert new user to table
    $stmt = $conn->prepare("INSERT INTO credentials (name, student_id, email, password) VALUES (?, ?, ?, ?)");

    if ($stmt === false) { //error out if statment fails
        displayError();
    }

    $stmt->bind_param("ssss", $name, $student_id, $email, $hashed_password); // bind the user info to statement, binding hashed password not normal password so no sensitive user data stored
    
    if(!$stmt->execute()){ // run statement to add user
        displayError(); // generic error message if statment fails
    }; 

    $stmt->close();

    // tell user that account has been created then refresh the page after a bit to let them log in
    echo "<p>Account successfully created! Please login to continue.</p>";
    if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
        $conn->close();
    }
    header("refresh:5;url=index.php");
    exit();
}

// hadling login here
if (isset($_POST['login'])) { // check to see if login form was submitted
    $student_id = sanitize($_POST['login_student_id']); // trim username and get it from the form
    $password = sanitize($_POST['login_password']); // do same with password and get it fromt he form

    if (empty($student_id) || empty($password)) {
        echo "Please provide Student ID and Password."; // get angry if form is empty
        if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
            $conn->close();
        }
        exit();
    }

    try{
        $stmt = $conn->prepare("SELECT id, password FROM credentials WHERE student_id = ?"); // prep statement to prevent injection
        
        if ($stmt === false) {
            //throw errors if statement isnt prepared properly
            displayError();
        }

        $stmt->bind_param("s", $student_id); // bind student id to statement
        $stmt->execute();
        $stmt->bind_result($user_id, $hashed_password); // bind output to statement
        if ($stmt->fetch()) { //check if statement worked and password is correct
            if (password_verify($password, $hashed_password)) { // take password and compare it with old password
                // regenerate the session id so sessions cant be fixed (as easily)
                session_regenerate_id(true);

                // store info to session variables
                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_agent_hash'] = hash('sha256', $_SERVER['HTTP_USER_AGENT']);
                $_SESSION['last_activity'] = time();
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];

                // redurect user, send to homepage
                header("Location: main_page.php");
                if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection before every exit call not just at the end
                    $conn->close();
                }
                exit();
            } else {
                echo "Invalid Student ID or Password.";
            }
        } else {
            echo "Invalid Student ID or Password.";
        }
        $stmt->close();
    } catch(Exception $e) {
        displayError();
    }
        
}

$conn->close();


echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Landing Page</title>
    <script>
    function $(id) {
        return document.getElementById(id);
    }

    // display errors
    function displayErrors(errors) {
        alert(errors.join("\\n"));
    }

    // Client-side validation 
    function validateSignupForm(form) {
        // use the $ function to get all of the values from the form
        let name = $('name').value.trim();
        let student_id = $('student_id').value.trim();
        let email = $('email').value.trim();
        let password = $('password').value;

        let errors = []; // make var to store errors in

        // add errors to error var if requirments not met
        if (name === "") {
            errors.push("Name is required.");
        }
        if (!/^[0-9]{9}$/.test(student_id)) {
            errors.push("Student ID must be exactly 9 digits.");
        }
        if (!/^[^@]+@sjsu\.edu$/.test(email)) {
            errors.push("Email must be an sjsu.edu email.");
        }
        if (password.length < 7 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
            errors.push("Password must be >6 chars, and include at least one uppercase letter, one lowercase letter, and one number.");
        }

        if (errors.length > 0) { // if errors not empty display them to user and return false so we dont proceed
            displayErrors(errors);
            return false;
        }

        return true; // if errors empty return true so we can proceed
    }

    function validateLoginForm(form) {
        // use $ function to get all of the values form the form
        let student_id = $('login_student_id').value.trim();
        let password = $('login_password').value;

        let errors = []; // make var to store errors in

        // make sure that user provided their student id and password 
        if (!/^[0-9]{9}$/.test(student_id)) {
            errors.push("Student ID must be exactly 9 digits.");
        }
        if (password === "") {
            errors.push("Password is required.");
        }

        if (errors.length > 0) {
            displayErrors(errors);
            return false;
        }

        return true; // return true so we can proceed
    }
    </script>

</head>
<body>
    <h1>Login or Sign-Up</h1>

    <h2>Login</h2>
    <form method="post" onsubmit="return validateLoginForm(this);" novalidate>
        <label>Student ID: <input type="text" name="login_student_id" id="login_student_id" maxlength="9" required></label><br>
        <label>Password: <input type="password" name="login_password" id="login_password" required></label><br>
        <input type="submit" name="login" value="Login">
    </form>

    <h2>Sign Up</h2>
    <form method="post" onsubmit="return validateSignupForm(this);" novalidate>
        <label>Name: <input type="text" name="name" id="name" required></label><br>
        <label>Student ID: <input type="text" name="student_id" id="student_id" maxlength="9" required></label><br>
        <label>Email: <input type="text" name="email" id="email" required></label><br>
        <label>Password: <input type="password" name="password" id="password" required></label><br>
        <input type="submit" name="signup" value="Sign Up">
    </form>

</body>
</html>
HTML;
?>



