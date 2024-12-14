<?php
session_start();
require_once "login.php";
require_once "utilities.php";
define('TIMEOUT_DURATION', 1800);


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
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > TIMEOUT_DURATION) {
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

/*---------------------------------------encryption menus------------------------------*/

if (isset($_POST['encrypt_submit'])) {
    $encryption_algorithm = sanitize($_POST['encryption_algorithm']); //sanitize the input field 
    $allowed_algorithms = ['RC4', 'DoubleTranspose', 'SimpleSub']; // change these to whatever we end up naming

    // Make sure algorithm is valid (shouldnt really be needed as selection is a drop down menu)
    if (!in_array($encryption_algorithm, $allowed_algorithms)) {
        $query_results = "Invalid encryption algorithm selected.";
    } else {
        $original_data = "";
        $filename = null;

        // check if text box has data
        if (!empty($_POST['text_data'])) {
            $original_data = sanitize($_POST['text_data']);
        }

        // Check if file was uploaded
        if (isset($_FILES['file_data']) && $_FILES['file_data']['error'] === UPLOAD_ERR_OK) {
            // Sanitize file name
            $filename = basename($_FILES['file_data']['name']);
            $filename = preg_replace("/[^a-zA-Z0-9._-]/", "_", $filename);
            $filename = sanitize($filename)
            // Get the file contents
            $file_contents = file_get_contents(sanitize($_FILES['file_data']['tmp_name']));
            // Sanitize file contents
            $file_contents = sanitize($file_contents);

            // TODO flesh this out to make sure that its clear what we encrypt, and make sure one is provided
            $original_data = !empty($file_contents) ? $file_contents : $original_data;
        }

        if (empty($original_data)) {
            $query_results = "No data provided to encrypt.";
        } else {
            // Encrypt the data based on chosen algorithm
            switch ($encryption_algorithm) {
                case 'RC4':
                    $encrypted_data = encryptWithRC4($original_data);
                    break;
                case 'DoubleTranspose':
                    $encrypted_data = encryptWithDoubleTranspose($original_data);
                    break;
                case 'SimpleSub':
                    $encrypted_data = encryptWithSimpleSub($original_data);
                    break;
                default:
                    $query_results = "Invalid encryption algorithm.";
                    $encrypted_data = null;
            }

            if ($encrypted_data !== null) {
                // Store results to db
                $stmt = $conn->prepare("INSERT INTO encrypted_data (user_id, original_data, encrypted_data, algorithm, filename) VALUES (?, ?, ?, ?, ?)");
                if ($stmt === false) {
                    displayError();
                }
                $user_id = $_SESSION['user_id'];
                $stmt->bind_param("issss", $user_id, $original_data, $encrypted_data, $encryption_algorithm, $filename);
                if (!$stmt->execute()) { 
                    displayError(); 
                }
                $stmt->close();
                $inserted_id = $conn->insert_id;

                // Display the data
                $safe_encrypted_data = htmlspecialchars($encrypted_data, ENT_QUOTES, 'UTF-8');
                $query_results = "Data encrypted and stored successfully.<br>
                                  <strong>Encrypted Data:</strong><br>
                                  <pre>{$safe_encrypted_data}</pre>";
            }
            //TODO make a new page that allows user to download previouse data that they have encrypted as we are storing it anyway
        }
    }
}

/*---------------------------------------encryption menus------------------------------*/

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
    //TODO make sure to integrate client side validation VERY IMPORTANT
    </script>

</head>
<body>
    <h1>Encryptotron9000</h1>
    <p>{$query_results}</p>
    <form method="post" enctype="multipart/form-data">
        <h2>Encrypt Your Data</h2>
        <label>Enter text data (optional):<br>
            <textarea name="text_data" rows="5" cols="40"></textarea>
        </label><br><br>
        <label>Or upload a file (optional):<br>
            <input type="file" name="file_data">
        </label><br><br>
        <label>Select Encryption Algorithm:<br>
            <select name="encryption_algorithm">
                <option value="RC4">Algorithm 1</option>
                <option value="DoubleTranspose">Algorithm 2</option>
                <option value="SimpleSub">Algorithm 3</option>
            </select>
        </label><br><br>
        <input type="submit" name="encrypt_submit" value="Encrypt">
    </form>

    <form method="post">
        <input type="submit" name="logout" value="Log Out">
    </form>
</body>
</html>
HTML;
?>

