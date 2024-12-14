<?php
session_start();
require_once "login.php";
require_once "utilities.php"
$timeout_duration = 1800;

/*----------------------------------------------------------Session_Validation---------------------------------------------------------------------------*/

//check if user is logged in
if (!isset($_SESSION['user_id'])) {
    // if user is not logged in redirect them to login page
    header("Location: index.php");
    exit();
}

// try and stop session hijacking(check for it)
if (!isset($_SESSION['ip_address']) || $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR'] ||
    !isset($_SESSION['user_agent']) || $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    // destroy session and redirect if anything goes wrong
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}

//make sure that the user agent hash lines up and destroy session if it does not
if (!isset($_SESSION['user_agent_hash']) || $_SESSION['user_agent_hash'] !== hash('sha256', $_SERVER['HTTP_USER_AGENT'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}

//expire session after a bit of time
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout_duration) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}
$_SESSION['last_activity'] = time();

/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/

//connect to the database
try {
    $conn = new mysqli($servername, $db_username, $db_password, $dbname); // create connection to database
    $conn->set_charset("utf8mb4"); 
} catch (mysqli_sql_exception $e) {
    // generic error if connection fails
    displayError();
}

// Handle Logout here
if (isset($_POST['logout'])) {
    //destroy the session
    session_unset();
    session_destroy();  
    if (isset($conn) && $conn instanceof mysqli) { // make sure to close the connection when user logs out this time
        $conn->close();
    }
    //redirect user to login page
    header("Location: index.php");
    exit();
}

$query_results = ""; // var to store results

if (isset($_POST['search'])) {
    $student_name = sanitize($_POST['student_name']); // get student name and sanitize it
    $student_id = sanitize($_POST['student_id']); // get student id and sanitize it
    $student_id_last_two = (int) substr($student_id, -2); // get only the last 2 digits of the student id

    // check if any issues with student name or id this shouldnt happen because client side validation
    if (empty($student_name) || !preg_match('/^[0-9]{9}$/', $student_id)) {
        $query_results = "Invalid input. Make sure Student ID is 9 digits and name is not empty."; // store issue to results var
    } else {
        // prep statement to get users advisor
        $stmt = $conn->prepare("SELECT id, name, email, phone FROM advisors WHERE lower_bound <= ? AND upper_bound >= ?");
        if ($stmt === false) {
            displayError();
        }

        $stmt->bind_param("ii", $student_id_last_two, $student_id_last_two); // bind student id to statement
        $stmt->execute();
        $stmt->bind_result($adv_id, $adv_name, $adv_email, $adv_phone); // bind results to statement
        if ($stmt->fetch()) { // if statement returned results add them to results var for display
            $query_results = "Advisor: ".sanitize($adv_name)."<br>Email: ".sanitize($adv_email)."<br>ID: ".sanitize($adv_id)."<br>Phone: ".sanitize($adv_phone);
        } else {
            $query_results = "No advisor found for this Student ID."; // otherwise say no id found and let it be displayed later
        }
        $stmt->close();
    }
}

$conn->close();


echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Main Page</title>
    <script>
    function $(id) {
        return document.getElementById(id);
    }

    function displayErrors(errors) {
        alert(errors.join("\\n"));
    }

    function validateSearchForm(form) {
        // user $ function to get information from form
        let student_name = $('student_name').value.trim();
        let student_id = $('student_id').value.trim();

        let errors = []; // create errors var to store errors

        // check for user input errors and store them if they occur for later display
        if (student_name === ""){
            errors.push("Student name is required.");// tell user name needs to exist
        }

        if (!/^[0-9]{9}$/.test(student_id)) {
            errors.push("Student ID must be exactly 9 digits."); // tell user proper id format
        }

        if (errors.length > 0) {
            displayErrors(errors);
            return false;
        }
        
        return true; // return true and let us proceed otherwise
    }
    </script>

</head>
<body>
    <h1>Welcome to the Advisor Lookup</h1>
    <form method="post" onsubmit="return validateSearchForm(this);" novalidate>
        <label>Student Name: <input type="text"  name="student_name" id="student_name" required></label><br>
        <label>Student ID: <input type="text" name="student_id" id="student_id"  maxlength="9" required></label><br>
        <input type="submit" name="search" value="Search Advisor">
    </form>

    <p>{$query_results}</p>

    <form method="post">
        <input type="submit" name="logout" value="Log Out">
    </form>
</body>
</html>
HTML;
?>

