// datasets/demo_vuln.js
// Small demo Express app with a few common vulnerabilities for testing only.

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();

app.use(bodyParser.urlencoded({ extended: false }));

// 1) SQL Injection: unsafely concatenating user input into SQL
app.get('/user', (req, res) => {
  const username = req.query.username || '';
  // ⚠️ Vulnerable: string concatenation leads to SQL injection
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  const db = new sqlite3.Database(':memory:');
  db.serialize(() => {
    db.all(query, (err, rows) => {
      if (err) return res.status(500).send('DB error');
      res.json(rows);
    });
  });
});

// 2) Command injection: using child_process.exec with user input
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  // ⚠️ Vulnerable if host contains shell metacharacters
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).send('Ping failed');
    res.type('text/plain').send(stdout);
  });
});

// 3) Unsafe eval (bad practice)
app.post('/calc', (req, res) => {
  const expr = req.body.expr || '2+2';
  // ⚠️ Vulnerable: using eval on user-provided data
  try {
    const result = eval(expr);
    res.send(String(result));
  } catch (e) {
    res.status(400).send('Invalid expression');
  }
});

app.listen(3000, () => console.log('Demo app listening on :3000'));