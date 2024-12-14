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
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt = 0)
    {
        
    }
    else{
        
    }

}

function encryptWithDoubleTranspose($crypt ,$keyword1, $keyword2, $text){
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt = 0)
    {
        
    }
    else{

    }
}

funciton encryptWithRC4($crypt, $key, $text){
    //If crypt is 0 then we are encrypting else we are decrypting 
    if($crypt = 0)
    {
        
    }
    else{
        
    }
}

?>