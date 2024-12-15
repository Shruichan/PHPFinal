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
    $dictionary = array_merge(range('a', 'z'), range('A', 'Z'));
    $numDict = range(0, 9);
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt == 0)
    {
        //shift the dictionary right by however many shifts
        for($x = 0; $x < $shift; $x++){
            array_unshift($dictionary, array_pop($dictionary));
            array_unshift($numDict, array_pop($numDict));
        }
        for($i = 0; $i < count($original); $i++){
            if(in_array($original[$i], $dictionary)){
                $index = array_search($original[$i], $dictionary);
                $original[$i] = $dictionary[$index];
            }
            if(in_array($original[$i], $numDict)){
                $index = array_search($original[$i], $numDict);
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
            if(in_array($original[$i], $dictionary)){
                $index = array_search($original[$i], $dictionary);
                $original[$i] = $dictionary[$index];
            }
            if(in_array($original[$i], $numDict)){
                $index = array_search($original[$i], $numDict);
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

function encryptWithRC4($crypt, $key, $text){
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt == 0)
    {
        
    }
    else{
        
    }
}

?>