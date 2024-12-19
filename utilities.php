<?php

//----------------------------Helper Functions----------------------------------------------------


function sanitize($data) {
    $data = trim($data);
    $data = stripslashes($data);
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

function displayError() {
    echo "An unexpected error occurred. Please try again later.";
    exit();
}



//----------------------------Simple Substitution Implementation-----------------------------------



//susbstitution cypher via caesar cipher
function encryptWithSimpleSub($crypt, $shift, $text){
    $original = str_split($text); // split text into array of characters
    //Create a dictionary based on how many shifts given by the user
    $alph = array_merge(range('a', 'z'), range('A', 'Z'));
    $dictionary = array_merge(range('a', 'z'), range('A', 'Z')); // shift alphabet over to get new shifted dictionary
    // create arrays to store original positions
    $num = range('0', '9');
    $numDict = range('0', '9');

    if($crypt == "encrypt") // check if we are encrypting or decrypting
    {
        // handling encryption case
        for($x = 0; $x < $shift; $x++){ //shift the dictionary right by however many shifts
            // move last element of dictionary to the front
            array_unshift($dictionary, array_pop($dictionary));
            // move last element of numdict to front as well
            array_unshift($numDict, array_pop($numDict));
        }
        //replacing each character of thhe original text with its shifted counterpart
        for($i = 0; $i < count($original); $i++){
            if(in_array($original[$i], $alph)){
                /* if character is in array, find the original character and replace 
                    with the corresponding character in dictionary */
                $index = array_search($original[$i], $alph);
                $original[$i] = $dictionary[$index];
            }
            if(in_array($original[$i], $numDict)){
                /* if the character is a digit shift it using the num dict */
                $index = array_search($original[$i], $num);
                $original[$i] = $numDict[$index];
            }
        }
    }
    else{
        //shift to the left by however many shifts
        for($x = 0; $x < $shift; $x++){
            // move the first element of dictionary to the end
            array_push($dictionary, array_shift($dictionary));
            // move the first element of numdict ot the end
            array_push($numDict, array_shift($numDict));
        }
        for($i = 0; $i < count($original); $i++){
            if(in_array($original[$i], $alph)){
                // if character is a letter find its index
                $index = array_search($original[$i], $alph);
                // replace it with the character from the shifted array
                $original[$i] = $dictionary[$index];
            }
            if(in_array($original[$i], $num)){
                //if character is a digit find its index
                $index = array_search($original[$i], $num);
                // replace it with shifted didget from numdict
                $original[$i] = $numDict[$index];
            }
        }
    }
    return implode($original); // join characters back into a string and return them
}


//----------------------------Double Transposition Implementation-----------------------------------


function encryptWithDoubleTranspose($crypt ,$keyword1, $keyword2, $text){
    //Make keywords into lowercase and an array and distinguish any duplicate letters
    $k1 = str_split(strtolower($keyword1));
    $k2 = str_split(strtolower($keyword2));
    //Create list of duplicate letters for each one only needing the key number
    $u1 = array_keys(array_diff_assoc($k1, array_unique($k1)));
    $u2 = array_keys(array_diff_assoc($k2, array_unique($k2)));
    //Check if each keyword has duplicate letters
    if(count($u1) > 0)
    {
        //For each duplicate append its key number to the end.
        foreach($u1 as $num){
            $k1[$num] .= $num; 
        }
    }
    if(count($u2) > 0)
    {
        //For each duplicate append its key number to the end.
        foreach($u2 as $num){
            $k2[$num] .= $num; 
        }
    }

    // empty string to store the final result
    $result = "";
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt == "encrypt")
    {
        // do the first transposition using first keyword and original text
        $firstTranspose = transpose($k1, $text); 
        // do the second transposition using keyword 2 and result of first transposition
        $result = transpose($k2, $firstTranspose);
    }
    else{
        // do the first reverse transposition using k2 and ciphertext
        $firstTranspose = reverseTranspose($k2, $text);
        // do the second reverse transposition using k1 and the result of first reverse transposition
        $result = reverseTranspose($k1, $firstTranspose);
    }
    return $result; // return the result
}

function transpose($keyword, $text){
    $oldKey = $keyword; // store original order of keyword
    sort($keyword); // sort keyword alphabetically to determine transposition order

    // remove spaces from the text and split it into an array of characters 
    $original = str_split(str_replace(' ', '', $text));

    // calculate number of rows we need for grid
    $rowCount = intdiv(count($original) + count($keyword) - 1 , count($keyword));
    $result = []; // array to store grid rows after transposition
    //Begin placing text into a sorted grid
    $index = 0;
    for($i = 0; $i < $rowCount; $i++){
        $temp = []; // store one row of the grid
        // fill row column by column using keyword order for positioning
        for($j = 0; $j < count($keyword); $j++){
            // iff all characters from text place finalize current row
            if($index >= count($original)){
                ksort($temp); // sort row according to keyword column
                array_push($result, $temp); // add row to the grid
                break;
            }

            // get column index for the character using keywords original order
            $keyOrder = array_search($oldKey[$j], $keyword, true);
            
            //place the character in column position that was calculated
            $temp[$keyOrder] = $original[$index];

            // move to next character
            $index++;
        }

        // stop filling rows if we are at the end of the text
        if($index >= count($original)) break;

        // sort the row according to transposition order
        ksort($temp);

        // add the row to the grid
        array_push($result, $temp);
    }
    $index = 0; // track the character positions to add apaces
    $newText = "";
    for ($col = 0; $col < count($result[0]); $col++) {
        for ($row = 0; $row < count($result); $row++) {
            if(!isset($result[$row][$col])) break; // check if last row has incomplete section
            $newText .= $result[$row][$col];  // add character to final result
            // Add a space every 5 letters
            if (($index + 1) % 5 == 0 && $index + 1 < count($original)) {
                $newText .= ' ';
            }
            $index++;
            if($index >= count($original)) break; //Stop going through result if there are no more characters
        }
        if($index >= count($original)) break; //Stop going through result if there are no more characters
    }
    return $newText; // return transposed text as a single string
}

function reverseTranspose($keyword, $text){
    $oldKey = $keyword; // store original order of keywords
    sort($keyword); // sort keyword alphabetically
    $original = str_split(str_replace(' ', '', $text)); // remove spaces from text and split it into array of chars
    $rowCount = intdiv(count($original) + count($keyword) - 1 , count($keyword)); // calculate num rows
    $blocked = (count($keyword) * $rowCount) - count($original); //how many of the last row will be blocked off
    $result = array_fill(0, $rowCount, array_fill(0, count($keyword), "")); // make array with the correct number of rows and columns

    //Begin placing text into a sorted grid
    $index = 0; // track current character position in text
    // Go column by column filling in the grid
    for($j = 0; $j < count($keyword); $j++){
        for($i = 0 ;$i < $rowCount; $i++){
            // get column index for the character using keywords original order
            $keyOrder = array_search($keyword[$j], $oldKey, true);

            // Check if the column is the one that is needed to be blocked on the last row
            if($keyOrder > $blocked && $i === $rowCount - 1) break;

            // Place the character in the correct column and row
            $result[$i][$keyOrder] = $original[$index];
           
            // Move to next character
            $index++;
            if($index >= count($original)) break; //Stop adding to result if no more characters
        }
        if($index >= count($original)) break; //Stop going through result if there are no more characters
    }

    $index = 0; // track position to add spaces
    $newText = "";
    foreach ($result as $row) {
        foreach ($row as $element) {
            $newText .= $element;  // add character to the final result
            // Add a space every 5 letters
            if (($index + 1) % 5 == 0 && $index + 1 < count($original)) {
                $newText .= ' ';
            }
            $index++;
            if($index >= count($original)) break; //Stop going through result if there are no more characters
        }
        if($index >= count($original)) break; //Stop going through result if there are no more characters
    }
    return $newText; // return reverse transposed text as a single string
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