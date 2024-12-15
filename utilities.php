<?php

function sanitize($data) {
    $data = trim($data);
    $data = stripslashes($data);
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

function displayError() {
    echo "An unexpected error occurred. Please try again later.";
    exit();
}

function encryptWithSimpleSub($crypt, $shift, $text){
    //If crypt is 0 then we are encrypting else we are decrypting 
    return('testing');
    if($crypt = 0)
    {
        
    }
    else{
        
    }

}

function encryptWithDoubleTranspose($crypt ,$keyword1, $keyword2, $text){
    //If crypt is 0 then we are encrypting else we are decrypting 
    return('testing');
    if($crypt = 0)
    {
        
    }
    else{

    }
}

// need to make sure that strings are binary
function ensureBinary($str) {
    // check if user already provided binary so we can just ignore and continue onwards
    if (preg_match('/^[01]+$/', $str)) {
        // Already binary
        return $str;
    } else {
        // convert text to binary if not binary
        $bin = '';
        for ($i = 0; $i < strlen($str); $i++) {
            $bin .= str_pad(decbin(ord($str[$i])), 8, '0', STR_PAD_LEFT);
        }
        return $bin;
    }
}


function encryptWithRC4($crypt, $key, $data){
    // $crypt: 0 is encrypt and 1 is decrypt
    $n = 3; // num bits we look at at a tim
    $key = ensureBinary($key);
    $data = ensureBinary($data);

    $pt = [];
    for ($i = 0; $i < strlen($data); $i += $n) {
        $chunk = substr($data, $i, $n);
        $pt[] = bindec($chunk);
    }

    $key_list = [];
    for ($i = 0; $i < strlen($key); $i += $n) {
        $chunk = substr($key, $i, $n);
        $key_list[] = bindec($chunk);
    }

    // Initialize state vector S
    $S = [];
    for ($i = 0; $i < (1 << $n); $i++) {
        $S[$i] = $i;
    }

    // Extend key_list if shorter than S
    $diff = count($S) - count($key_list);
    if ($diff > 0) {
        for ($i = 0; $i < $diff; $i++) {
            $key_list[] = $key_list[$i];
        }
    }



    // KSA (Key Scheduling Algorithm)
    $j = 0;
    $N = count($S);
    for ($i = 0; $i < $N; $i++) {
        $j = ($j + $S[$i] + $key_list[$i]) % $N;
        // Swap S[i] and S[j]
        $temp = $S[$i];
        $S[$i] = $S[$j];
        $S[$j] = $temp;
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    $i = 0;
    $j = 0;
    $key_stream = [];
    for ($k = 0; $k < count($pt); $k++) {
        $i = ($i + 1) % $N;
        $j = ($j + $S[$i]) % $N;
        $temp = $S[$i];
        $S[$i] = $S[$j];
        $S[$j] = $temp;

        $t = ($S[$i] + $S[$j]) % $N;
        $key_stream[] = $S[$t];
    }


    $result = [];
    for ($idx = 0; $idx < count($pt); $idx++) {
        $c = $pt[$idx] ^ $key_stream[$idx];
        $result[] = $c;
    }

    $output = "";
    foreach ($result as $val) {
        $binVal = decbin($val);
        // Pad with leading zeros to make it $n bits
        $binVal = str_pad($binVal, $n, "0", STR_PAD_LEFT);
        $output .= $binVal;
    }

    return $output;
}

?>