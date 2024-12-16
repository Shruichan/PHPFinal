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


//susbstitution cypher via caesar cipher
function encryptWithSimpleSub($crypt, $shift, $text){
    $original = str_split($text);
    //Create a dictionary based on how many shifts given by the user
    $alph = array_merge(range('a', 'z'), range('A', 'Z'));
    $dictionary = array_merge(range('a', 'z'), range('A', 'Z'));
    $num = range('0', '9');
    $numDict = range('0', '9');
    //If encrypt or decrypt
    if($crypt == "encrypt")
    {
        //shift the dictionary right by however many shifts
        for($x = 0; $x < $shift; $x++){
            array_unshift($dictionary, array_pop($dictionary));
            array_unshift($numDict, array_pop($numDict));
        }
        for($i = 0; $i < count($original); $i++){
            if(in_array($original[$i], $alph)){
                $index = array_search($original[$i], $alph);
                $original[$i] = $dictionary[$index];
            }
            if(in_array($original[$i], $numDict)){
                $index = array_search($original[$i], $num);
                $original[$i] = $numDict[$index];
            }
        }
    }
    else{
        //shift to the left by however many shifts
        for($x = 0; $x < $shift; $x++){
            array_push($dictionary, array_shift($dictionary));
            array_push($numDict, array_shift($numDict));
        }
        for($i = 0; $i < count($original); $i++){
            if(in_array($original[$i], $alph)){
                $index = array_search($original[$i], $alph);
                $original[$i] = $dictionary[$index];
            }
            if(in_array($original[$i], $num)){
                $index = array_search($original[$i], $num);
                $original[$i] = $numDict[$index];
            }
        }
    }
    return implode($original);
}

function encryptWithDoubleTranspose($crypt ,$keyword1, $keyword2, $text){
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt == 0)
    {
        
    }
    else{

    }
}


//----------------------------RC4 Implementation-----------------------------------



function ensureBinary($str) {
    if (preg_match('/^[01]+$/', $str)) {
        return $str; // just return the string if it is already binary
    } else {
        $bin = ''; //string to store the binary representation
        for ($i = 0; $i < strlen($str); $i++) { // loop over all characters in the string and convert to binary
            $bin .= str_pad(decbin(ord($str[$i])), 8, '0', STR_PAD_LEFT); // convert character to binary and pad it if not enough
        }
        return $bin; // return string after we append all the stuff to it
    }
}

function binaryStringToBytes($binaryStr) {
    $len = strlen($binaryStr); // get length
    if ($len % 8 !== 0) { // if string not multiple of 8 rc4 implementation no work so pad with 0s if so
        $binaryStr = str_pad($binaryStr, $len + (8 - $len % 8), '0', STR_PAD_RIGHT); // just pad it with 0s if its not in bytes
    }
    $bytes = ''; // string to store bytes
    for ($i = 0; $i < $len; $i += 8) { //loop every 8
        $byteBits = substr($binaryStr, $i, 8); // get the substring
        $bytes .= chr(bindec($byteBits)); // convert it to byte character
    }
    return $bytes; // return in bytes
}

function bytesToBinaryString($bytes) {
    $bin = ''; // var to store binary
    for ($i = 0; $i < strlen($bytes); $i++) {
        $bin .= str_pad(decbin(ord($bytes[$i])), 8, '0', STR_PAD_LEFT); // convert byte to its binary pad it if not enough and append to string
    }
    return $bin; // return the bytes
}


// this implementation referenced the pseudocode found on dcode (https://www.dcode.fr/rc4-cipher)
function rc4($keyBytes, $dataBytes) {
    //------------------------------ Key Scheduling Algorithm (KSA)

    $keyLength = strlen($keyBytes); // get key length in bytes
    // initialize the state vector with a range of 0->255
    $S = range(0, 255);
    $j = 0; // index variable for the KSA

    // perform the initial permuation of S running loop 256 times once for each value in s
    for ($i = 0; $i < 256; $i++) {
        // get new value of index J based on current value of S, the key and some modulus to make sure it stays in bounds
        $j = ($j + $S[$i] + ord($keyBytes[$i % $keyLength])) % 256;
        //swap values of s[i] and s[j]
        $temp = $S[$i];
        $S[$i] = $S[$j];
        $S[$j] = $temp;
    }


    //------------------------ Pseudo Random Generation Algorithm (PRGA)

    // initialize the indexes used for generating the keystream
    $i = 0;
    $j = 0;
    $output = ''; // empty string to store output

    //process every byte of the input data
    for ($n = 0; $n < strlen($dataBytes); $n++) {
        // increment i and let it loop back around using modulus
        $i = ($i + 1) % 256;
        // update J based on value of S[i]
        $j = ($j + $S[$i]) % 256;
        // swap s[i] and s[j] (for further randomization)
        $temp = $S[$i];
        $S[$i] = $S[$j];
        $S[$j] = $temp;

        // get the keydtream value by adding s[i] and s[j]
        // use the result as an index for state vector
        $K = $S[($S[$i] + $S[$j]) % 256];
        // XOR the current data byte with keystream value 
        $output .= chr(ord($dataBytes[$n]) ^ $K); // chr converts rusult back into character
    }
    //return result, rc4 is the same both ways so no need to differentiate between encryption and decryption
    return $output;
}

function encryptWithRC4($key, $data) {
    // make sure key and data are binary
    $binaryKey = ensureBinary($key);
    $binaryData = ensureBinary($data);
    
    // convert them into bytes
    $keyBytes = binaryStringToBytes($binaryKey);
    $dataBytes = binaryStringToBytes($binaryData);

    // perform rc4 and return the resultant bytes
    $resultBytes = rc4($keyBytes, $dataBytes);

    //convert bytes back into binary and return them 
    $resultBinary = bytesToBinaryString($resultBytes);
    return [
        'binary' => $resultBinary,
        'ascii' => $resultBytes, 
        'hexadecimal' => bin2hex($resultBytes),
        'octal' => implode('', array_map(function ($byte) { return decoct(bindec($byte)); }, str_split($resultBinary, 8))),
        'decimal' => implode(' ', array_map(function ($byte) {return bindec($byte); }, str_split($resultBinary, 8)))
    ];
}

?>