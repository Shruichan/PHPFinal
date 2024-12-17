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

    $encrypt_decrypt = sanitize($_POST['encrypt_decrypt']); //Whether data is encrypted or decrypted

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
            $filename = sanitize($filename);
            // Get the file contents
            $file_contents = file_get_contents($_FILES['file_data']['tmp_name']);
            // Sanitize file contents
            $file_contents = sanitize($file_contents);

            // TODO flesh this out to make sure that its clear what we encrypt, and make sure one is provided
            $original_data = !empty($file_contents) ? $file_contents : $original_data;
        }

        if (empty($original_data)) {
            $query_results = "No data provided to encrypt.";
        } else {
            if ($encryption_algorithm === 'RC4') {
                if (empty($_POST['encryption_key'])) {
                    $query_results = "RC4 algorithm requires a key.";
                } else {
                    $key = sanitize($_POST['encryption_key']);
                }

                if (!empty($key)) {
                    $return_format = isset($_POST['return_format']) ? sanitize($_POST['return_format']) : 'binary';
                    $allowed_formats = ['binary', 'ascii', 'hexadecimal', 'octal', 'decimal'];
                    if (!in_array($return_format, $allowed_formats)) {
                        $query_results = "Invalid return format selected for RC4.";
                        $encrypted_data = null;
                    }
                }

            }
            elseif($encryption_algorithm === 'SimpleSub'){
                if(empty($_POST['shift'])){
                    $query_results = "Simple substition algorithm requires a shift amount."; 
                }
                else{
                    $shift = sanitize($_POST['shift']);
                }
            }
            elseif ($encryption_algorithm === 'DoubleTranspose') {
                if (empty($_POST['key1']) || empty($_POST['key2'])) {
                    $query_results = "Double Transposition requires both Key 1 and Key 2.";
                } else {
                    $key1 = sanitize($_POST['key1']);
                    $key2 = sanitize($_POST['key2']);
                }
            }else{
                
            }
            // Encrypt/Decrypt the data based on chosen algorithm
            switch ($encryption_algorithm) {
                case 'RC4':
                    if (!empty($key) && isset($return_format)) {
                        $encrypted_array = encryptWithRC4($key, $original_data);
                        $encrypted_data = $encrypted_array[$return_format];
                    } else {
                        $encrypted_data = null;
                    }
                    break;
                case 'DoubleTranspose':
                    $encrypted_data = encryptWithDoubleTranspose($encrypt_decrypt, "key1", "key2", $original_data);
                    break;
                case 'SimpleSub':
                    if(!empty($shift))
                    $encrypted_data = encryptWithSimpleSub($encrypt_decrypt, $shift, $original_data);
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
                $safe_encrypted_data = sanitize($encrypted_data);
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

    function validateEncryptionForm(form) {
        let errors = [];
        
        let text_data = $('text_data').value.trim();
        let file_data = $('file_data').value.trim();
        let algorithm = $('encryption_algorithm').value;
        let encrypt_decrypt = form.encrypt_decrypt.value;
        if (text_data === "" && file_data === "") {
            errors.push("Please provide text data or upload a file.");
        }
        if (algorithm === "RC4") {
            let key = $('encryption_key').value.trim();
            if (key === "") {
                errors.push("RC4 requires a key.");
            }
            let return_format = $('return_format_select').value;
            if (!["binary", "ascii", "hexadecimal", "octal", "decimal"].includes(return_format)) {
                errors.push("Invalid return format selected for RC4.");
            }
        } else if (algorithm === "SimpleSub") {
            let shiftVal = $('shift').value.trim();
            if (shiftVal === "") {
                errors.push("Simple Substitution requires a shift amount.");
            } else if (isNaN(shiftVal)) {
                errors.push("Shift must be a number.");
            }
        } else if (algorithm === "DoubleTranspose") {
            let key1Val = $('key1').value.trim();
            let key2Val = $('key2').value.trim();
            if (key1Val === "" || key2Val === "") {
                errors.push("Double Transposition requires both Key 1 and Key 2.");
            }
        }

        if (errors.length > 0) {
            displayErrors(errors);
            return false;
        }

        return true;
    }

    function toggleKeyInput() {
        const algorithm = $('encryption_algorithm').value;
        const keyInput = $('key_input');
        const doubleTransposeKeys = $('double_transpose_keys');
        const returnFormat = $('return_format');
        const shiftInput = $('shift_input');

        $('encryption_key').required = false;
        $('return_format_select').required = false;
        $('shift').required = false;
        $('key1').required = false;
        $('key2').required = false;

        if (algorithm === "RC4") {
            keyInput.style.display = "block";
            returnFormat.style.display = "block";
            shiftInput.style.display = "none";
            doubleTransposeKeys.style.display = "none";

            $('encryption_key').required = true;
            $('return_format_select').required = true;

        } else if (algorithm === "SimpleSub") {
            shiftInput.style.display = "block";
            returnFormat.style.display = "none";
            keyInput.style.display = "none";
            doubleTransposeKeys.style.display = "none";

            $('shift').required = true;

        } else if (algorithm === "DoubleTranspose") {
            doubleTransposeKeys.style.display = "block";
            keyInput.style.display = "none";
            shiftInput.style.display = "none";
            returnFormat.style.display = "none";

            $('key1').required = true;
            $('key2').required = true;

        } else {
            keyInput.style.display = "none";
            returnFormat.style.display = "none";
            shiftInput.style.display = "none";
            doubleTransposeKeys.style.display = "none";
        }
    }
    </script>
</head>
<body onload="toggleKeyInput()">
    <h1>Encryptotron9000</h1>
    <p>{$query_results}</p>
    <form method="post" enctype="multipart/form-data" onsubmit="return validateEncryptionForm(this);" novalidate>
        <h2>Encrypt Your Data</h2>
        <label>Enter text data (optional):<br>
            <textarea name="text_data" id="text_data" rows="5" cols="40"></textarea>
        </label><br><br>
        <label>Or upload a file (optional):<br>
            <input type="file" name="file_data" id="file_data">
        </label><br><br>
        <label>Select Encryption Algorithm:<br>
            <select name="encryption_algorithm" id="encryption_algorithm" required onchange="toggleKeyInput()">
                <option value="RC4">RC4</option>
                <option value="DoubleTranspose">Double Transposition</option>
                <option value="SimpleSub">Simple Substitution</option>
            </select>
        </label><br><br>
        <label>Select Encrypt or Decrypt:<br>
            <select name="encrypt_decrypt" required>
                <option value="encrypt">Encrypt</option>
                <option value="decrypt">Decrypt</option>
            </select>
        </label><br><br>

        <div id="key_input" style="display:none;">
            <label>Enter RC4 Key:<br>
                <input type="text" name="encryption_key" id="encryption_key" placeholder="Enter RC4 key">
            </label><br><br>
        </div>

        <div id="return_format" style="display:none;">
            <label>Select Return Format:<br>
                <select name="return_format" id="return_format_select">
                    <option value="binary">Binary</option>
                    <option value="ascii">ASCII</option>
                    <option value="hexadecimal">Hexadecimal</option>
                    <option value="octal">Octal</option>
                    <option value="decimal">Decimal</option>
                </select>
            </label><br><br>
        </div>

        <div id="double_transpose_keys" style="display:none;">
            <label>Enter Key 1:<br>
                <input type="text" name="key1" id="key1" placeholder="Enter first key">
            </label><br><br>
            <label>Enter Key 2:<br>
                <input type="text" name="key2" id="key2" placeholder="Enter second key">
            </label><br><br>
        </div>

        <div id="shift_input" style="display:none;">
            <label>Enter Shift Amount :<br>
                <input type="number" name="shift" id="shift" placeholder="Enter shift for cipher">
            </label><br><br>
        </div>

        <input type="submit" name="encrypt_submit" value="Encrypt/Decrypt">
    </form>

    <form method="post">
        <input type="submit" name="logout" value="Log Out">
    </form>
</body>
</html>
HTML;
?>