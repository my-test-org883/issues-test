const express = require('express');
const app = express();

app.use(express.json());

// ReDoS vulnerability #1: Email validation
app.post('/validate-email', (req, res) => {
    const email = req.body.email;

    // Vulnerable regex: Catastrophic backtracking
    // Input like "a@a.a" + "a".repeat(50000) + "!" causes ReDoS
    const emailRegex = /^([a-zA-Z0-9_\.-]+)@([a-zA-Z0-9_\.-]+)\.([a-zA-Z]{2,5})$/;

    const isValid = emailRegex.test(email);
    res.json({email, valid: isValid});
});

// ReDoS vulnerability #2: Username validation
app.post('/validate-username', (req, res) => {
    const username = req.body.username;

    // Vulnerable: Nested quantifiers cause exponential backtracking
    // Input like "a".repeat(30) + "!" causes ReDoS
    const usernameRegex = /^(a+)+$/;

    const isValid = usernameRegex.test(username);
    res.json({username, valid: isValid});
});

// ReDoS vulnerability #3: URL validation
app.post('/validate-url', (req, res) => {
    const url = req.body.url;

    // Vulnerable: Complex regex with alternation and repetition
    // Can cause catastrophic backtracking with crafted input
    const urlRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;

    const isValid = urlRegex.test(url);
    res.json({url, valid: isValid});
});

// ReDoS vulnerability #4: Password complexity check
app.post('/validate-password', (req, res) => {
    const password = req.body.password;

    // Vulnerable: Multiple overlapping groups
    // Input like "A" + "a".repeat(50) + "!" causes ReDoS
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    const isValid = passwordRegex.test(password);
    res.json({password, valid: isValid});
});

// ReDoS vulnerability #5: HTML tag validation
app.post('/validate-html', (req, res) => {
    const html = req.body.html;

    // Vulnerable: Nested groups with quantifiers
    // Crafted input can cause exponential time complexity
    const htmlRegex = /<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)/;

    const isValid = htmlRegex.test(html);
    res.json({html, valid: isValid});
});

// ReDoS vulnerability #6: JSON validation
app.post('/validate-json-string', (req, res) => {
    const jsonStr = req.body.json;

    // Vulnerable: Alternation with repetition
    // Input like '"' + 'a'.repeat(50000) + 'X' causes ReDoS
    const jsonRegex = /^"(\\.|[^"\\])*"$/;

    const isValid = jsonRegex.test(jsonStr);
    res.json({json: jsonStr, valid: isValid});
});

// ReDoS vulnerability #7: Phone number validation
app.post('/validate-phone', (req, res) => {
    const phone = req.body.phone;

    // Vulnerable: Complex pattern with optional groups
    // Can cause catastrophic backtracking
    const phoneRegex = /^(\+\d{1,3}[- ]?)?\d{10}$/;

    const isValid = phoneRegex.test(phone);
    res.json({phone, valid: isValid});
});

// ReDoS vulnerability #8: IPv4 validation
app.post('/validate-ip', (req, res) => {
    const ip = req.body.ip;

    // Vulnerable: Nested quantifiers
    // Input like "1.1.1." + "1".repeat(100000) causes ReDoS
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    const isValid = ipRegex.test(ip);
    res.json({ip, valid: isValid});
});

app.listen(3001, () => {
    console.log('ReDoS vulnerable app running on port 3001');
});