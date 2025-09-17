const express = require('express');
const app = express();
const lodash = require('lodash');

app.use(express.json());

// Prototype pollution vulnerability #1: Direct object assignment
app.post('/merge', (req, res) => {
    const target = {};

    // Vulnerable: Direct merge without sanitization
    // Payload: {"__proto__": {"polluted": true}}
    Object.assign(target, req.body);

    res.json({message: 'Objects merged', result: target});
});

// Prototype pollution vulnerability #2: Recursive merge function
function deepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            // Vulnerable: No protection against __proto__
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/deep-merge', (req, res) => {
    const config = {};
    // Vulnerable: Using unsafe merge function
    deepMerge(config, req.body);

    res.json({message: 'Deep merge completed', config: config});
});

// Prototype pollution vulnerability #3: lodash merge (vulnerable versions)
app.post('/lodash-merge', (req, res) => {
    const options = {};

    // Vulnerable: Using lodash.merge without validation
    // Vulnerable in lodash < 4.17.12
    lodash.merge(options, req.body);

    res.json({message: 'Lodash merge completed', options: options});
});

// Prototype pollution vulnerability #4: JSON parsing with reviver
app.post('/json-parse', (req, res) => {
    const jsonString = req.body.data;

    // Vulnerable: JSON.parse with unsafe reviver
    const parsed = JSON.parse(jsonString, (key, value) => {
        // This reviver doesn't protect against prototype pollution
        if (typeof value === 'object' && value !== null) {
            return Object.assign({}, value);
        }
        return value;
    });

    res.json({message: 'JSON parsed', data: parsed});
});

// Vulnerability #5: Manual property assignment
app.post('/set-property', (req, res) => {
    const obj = {};
    const {key, value} = req.body;

    // Vulnerable: Direct property assignment without validation
    // Payload: {"key": "__proto__.polluted", "value": true}
    const keys = key.split('.');
    let current = obj;

    for (let i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) current[keys[i]] = {};
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;

    res.json({message: 'Property set', object: obj});
});

// Check if pollution worked
app.get('/check-pollution', (req, res) => {
    const testObj = {};
    res.json({
        polluted: testObj.polluted,
        message: testObj.polluted ? 'Prototype pollution successful!' : 'No pollution detected'
    });
});

app.listen(3000, () => {
    console.log('Vulnerable app running on port 3000');
});