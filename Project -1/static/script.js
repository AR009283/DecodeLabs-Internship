const passwordInput = document.getElementById("password");

const togglePassword = document.getElementById("togglePassword");

const progressBar = document.getElementById("progressBar");

const strengthText = document.getElementById("strengthText");

const scoreText = document.getElementById("scoreText");

const suggestionsList = document.getElementById("suggestionsList");


// Requirement elements

const lengthCheck = document.getElementById("length");
const upperCheck = document.getElementById("uppercase");
const lowerCheck = document.getElementById("lowercase");
const numberCheck = document.getElementById("number");
const symbolCheck = document.getElementById("symbol");


// Password checking function

passwordInput.addEventListener("input", checkPassword);


function checkPassword(){

    let password = passwordInput.value;

    let score = 0;

    let suggestions = [];


    // Conditions

    let hasLength = password.length >= 8;

    let hasUpper = /[A-Z]/.test(password);

    let hasLower = /[a-z]/.test(password);

    let hasNumber = /[0-9]/.test(password);

    let hasSymbol = /[^A-Za-z0-9]/.test(password);



    // Update requirements

    updateRequirement(lengthCheck,hasLength,"At least 8 characters");

    updateRequirement(upperCheck,hasUpper,"One uppercase letter");

    updateRequirement(lowerCheck,hasLower,"One lowercase letter");

    updateRequirement(numberCheck,hasNumber,"One number");

    updateRequirement(symbolCheck,hasSymbol,"One special character");



    // Score calculation

    if(hasLength)
        score += 20;

    if(hasUpper)
        score += 20;

    if(hasLower)
        score += 20;

    if(hasNumber)
        score += 20;

    if(hasSymbol)
        score += 20;



    // Extra security points

    if(password.length >= 12)
        score += 10;


    if(password.length >= 16)
        score += 10;



    if(score > 100)
        score = 100;



    scoreText.innerHTML = score + " / 100";


    updateStrength(score);



    // Suggestions

    if(!hasLength)
        suggestions.push("Use at least 8 characters");


    if(!hasUpper)
        suggestions.push("Add uppercase letters");


    if(!hasLower)
        suggestions.push("Add lowercase letters");


    if(!hasNumber)
        suggestions.push("Include numbers");


    if(!hasSymbol)
        suggestions.push("Use special characters");


    if(password.length < 12)
        suggestions.push("Longer passwords are more secure");



    showSuggestions(suggestions);

}





// Requirement update

function updateRequirement(element,condition,text){

    if(condition){

        element.innerHTML = "✅ " + text;

        element.style.color="#22c55e";

    }

    else{

        element.innerHTML = "❌ " + text;

        element.style.color="#ef4444";

    }

}





// Strength display

function updateStrength(score){


    progressBar.style.width = score + "%";


    if(score <= 40){

        strengthText.innerHTML="Weak";

        strengthText.className="weak";

        progressBar.style.background="#ef4444";

    }


    else if(score <= 70){

        strengthText.innerHTML="Medium";

        strengthText.className="medium";

        progressBar.style.background="#facc15";

    }


    else{

        strengthText.innerHTML="Strong";

        strengthText.className="strong";

        progressBar.style.background="#22c55e";

    }


}





// Suggestions display

function showSuggestions(items){


    suggestionsList.innerHTML="";


    if(items.length===0){

        suggestionsList.innerHTML=
        "<li>🎉 Your password is strong!</li>";

        return;

    }


    items.forEach(item=>{

        let li=document.createElement("li");

        li.innerHTML="💡 "+item;

        suggestionsList.appendChild(li);

    });


}





// Show / Hide Password

togglePassword.addEventListener("click",()=>{


    if(passwordInput.type==="password"){

        passwordInput.type="text";

        togglePassword.innerHTML=
        '<i class="fa-solid fa-eye-slash"></i>';

    }


    else{

        passwordInput.type="password";

        togglePassword.innerHTML=
        '<i class="fa-solid fa-eye"></i>';

    }


});






// Generate Password







// Clear Button

document.getElementById("clearBtn")
.addEventListener("click",()=>{


    passwordInput.value="";


    progressBar.style.width="0%";


    strengthText.innerHTML="Waiting...";

    strengthText.className="";


    scoreText.innerHTML="0 / 100";


    suggestionsList.innerHTML=
    "<li>Start typing your password...</li>";



    updateRequirement(lengthCheck,false,"At least 8 characters");

    updateRequirement(upperCheck,false,"One uppercase letter");

    updateRequirement(lowerCheck,false,"One lowercase letter");

    updateRequirement(numberCheck,false,"One number");

    updateRequirement(symbolCheck,false,"One special character");


});