const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// XSS vulnerability #1: Reflected XSS in query parameter
app.get('/search', (req, res) => {
    const query = req.query.q;

    // Vulnerable: Direct insertion without escaping
    const html = `
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${query}</p>
            </body>
        </html>
    `;

    res.send(html);
});

// XSS vulnerability #2: DOM-based XSS
app.get('/profile', (req, res) => {
    const username = req.query.user;

    // Vulnerable: User input directly in script tag
    const html = `
        <html>
            <body>
                <h1 id="welcome"></h1>
                <script>
                    document.getElementById('welcome').innerHTML = 'Welcome ${username}!';
                </script>
            </body>
        </html>
    `;

    res.send(html);
});

// XSS vulnerability #3: innerHTML assignment
app.get('/message', (req, res) => {
    const msg = req.query.msg;

    // Vulnerable: Direct innerHTML assignment in client-side code
    const html = `
        <html>
            <body>
                <div id="message"></div>
                <script>
                    document.getElementById('message').innerHTML = '${msg}';
                </script>
            </body>
        </html>
    `;

    res.send(html);
});

// XSS vulnerability #4: Stored XSS simulation
const comments = [];

app.post('/comment', (req, res) => {
    const comment = req.body.comment;
    const author = req.body.author;

    // Vulnerable: Storing unsanitized user input
    comments.push({author, comment, timestamp: new Date()});

    res.redirect('/comments');
});

app.get('/comments', (req, res) => {
    let commentHtml = '';

    // Vulnerable: Outputting stored data without escaping
    comments.forEach(c => {
        commentHtml += `
            <div class="comment">
                <strong>${c.author}</strong>: ${c.comment}
                <small>(${c.timestamp})</small>
            </div>
        `;
    });

    const html = `
        <html>
            <body>
                <h1>Comments</h1>
                ${commentHtml}
                <form method="post" action="/comment">
                    <input name="author" placeholder="Name" required>
                    <textarea name="comment" placeholder="Comment" required></textarea>
                    <button type="submit">Add Comment</button>
                </form>
            </body>
        </html>
    `;

    res.send(html);
});

// XSS vulnerability #5: JavaScript execution via location
app.get('/redirect', (req, res) => {
    const url = req.query.url;

    // Vulnerable: Unvalidated redirect with script injection
    const html = `
        <html>
            <body>
                <p>Redirecting...</p>
                <script>
                    window.location = '${url}';
                </script>
            </body>
        </html>
    `;

    res.send(html);
});

// XSS vulnerability #6: Template injection
app.get('/template', (req, res) => {
    const name = req.query.name;
    const title = req.query.title || 'Default Title';

    // Vulnerable: Template with unescaped variables
    const template = `
        <html>
            <head><title>${title}</title></head>
            <body>
                <h1>Hello ${name}!</h1>
                <script>
                    var userName = '${name}';
                    console.log('User: ' + userName);
                </script>
            </body>
        </html>
    `;

    res.send(template);
});

app.listen(3002, () => {
    console.log('XSS vulnerable app running on port 3002');
});