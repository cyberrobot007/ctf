const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const CryptoJS = require('crypto-js');
const axios = require('axios');
const yaml = require('js-yaml');

const app = express();
const port = 3000;

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Challenge List (unchanged, but not shown in UI)
const challenges = [
  { id: 'A01', name: 'Challenge 1', path: '/a01', description: 'Access Denied', flag: 'FLAG{this_is_the_access_flag}' },
  { id: 'A02', name: 'Challenge 2', path: '/a02', description: 'Weak Crypto', flag: 'FLAG{weak_crypto_md5}' },
  { id: 'A03', name: 'Challenge 3', path: '/a03', description: 'SQL Shenanigans ', flag: 'FLAG{this_is_the_flag_you_seek}' },
  { id: 'A04', name: 'Challenge 4', path: '/a04', description: 'Transfer to another account', flag: 'FLAG{insecure_design_race}' },
  { id: 'A05', name: 'Challenge 5', path: '/a05', description: 'Exposed some jucy', flag: 'FLAG{misconfig_default_creds}' },
  { id: 'A06', name: 'Challenge 6', path: '/a06', description: 'Prototype Pollution', flag: 'FLAG{vuln_components_pollute}' },
  { id: 'A07', name: 'Challenge 7', path: '/a07', description: 'No Limit', flag: 'FLAG{auth_failure_brute}' },
  { id: 'A08', name: 'Challenge 8', path: '/a08', description: 'I believe in Deserialization', flag: 'FLAG{integrity_yaml_deser}' },
  { id: 'A09', name: 'Challenge 9', path: '/a09', description: 'Replay', flag: 'FLAG{logging_replay_fail}' },
  { id: 'A10', name: 'Challenge 10', path: '/a10', description: 'Internal Fetchy', flag: 'FLAG{ssrf_internal_access}' }
];

// Root route: Web Security Challenges Hub
app.get('/', (req, res) => {
  let challengeList = '<h1>Web Security Challenges</h1><p>Select a task to explore:</p><ul>';
  challenges.forEach(chall => {
    challengeList += `<li><a href="${chall.path}">${chall.name}</a> - ${chall.description}</li>`;
  });
  challengeList += '</ul>';
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Web Security Challenges</title></head>
    <body>
      ${challengeList}
    </body>
    </html>
  `);
});

// ==================== Challenge 1: Broken Access Control (IDOR) ====================
const dbA01 = new sqlite3.Database(':memory:');
dbA01.serialize(() => {
  dbA01.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    email TEXT,
    profile_data TEXT
  )`);

  const stmt = dbA01.prepare('INSERT INTO users (id, username, email, profile_data) VALUES (?, ?, ?, ?)');
  stmt.run(1, 'user1', 'user1@company.com', 'Welcome to your profile, user1!');
  stmt.run(2, 'user2', 'user2@company.com', 'You are a regular employee.');
  stmt.run(3, 'admin', 'admin@company.com', challenges[0].flag);
  stmt.finalize();
});

app.get('/a01', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Company Portal</title></head><body>
      <h1>Company Portal</h1>
      <p><a href="/">Back to Challenges</a></p>
      <p>Select your user ID to view your profile:</p>
      <form method="GET" action="/a01/profile">
        <input type="number" name="userId" placeholder="Enter User ID (e.g., 1 or 2)" required>
        <button type="submit">View Profile</button>
      </form>
      <p>Hint: Only access your own profile!</p>
    </body></html>
  `);
});

app.get('/a01/profile', (req, res) => {
  const userId = req.query.userId;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  console.log('Challenge 1 Query:', query);

  dbA01.get(query, (err, row) => {
    if (err) {
      res.status(500).send('Database error: ' + err.message);
    } else if (!row) {
      res.send(`
        <!DOCTYPE html>
        <html><head><title>Profile Not Found</title></head><body>
          <h1>Error</h1><p>No user found with ID ${userId}.</p>
          <a href="/a01">Back</a> | <a href="/">Challenges</a>
        </body></html>
      `);
    } else {
      res.send(`
        <!DOCTYPE html>
        <html><head><title>User Profile</title></head><body>
          <h1>User Profile</h1>
          <p><strong>ID:</strong> ${row.id}</p>
          <p><strong>Username:</strong> ${row.username}</p>
          <p><strong>Email:</strong> ${row.email}</p>
          <p><strong>Profile Data:</strong> ${row.profile_data}</p>
          <a href="/a01">Back</a> | <a href="/">Challenges</a>
        </body></html>
      `);
    }
  });
});

// ==================== Challenge 2: Cryptographic Failures (Weak MD5 Hashing) ====================
app.get('/a02', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Secure Vault</title></head><body>
      <h1>Secure Vault</h1>
      <p><a href="/">Back to Challenges</a></p>
      <p>Try to login as admin. Passwords are "securely" hashed.</p>
      <form method="POST" action="/a02/login">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
      </form>
      <p>Hint: Check browser dev tools or source for hash. Crack it!</p>
      <script>
        console.log('Admin hash: 5f4dcc3b5aa765d61d8327deb882cf99'); // MD5 of 'password'
      </script>
    </body></html>
  `);
});

app.post('/a02/login', (req, res) => {
  const { username, password } = req.body;
  const hashedPw = CryptoJS.MD5(password).toString();
  const adminHash = '5f4dcc3b5aa765d61d8327deb882cf99';

  if (username === 'admin' && hashedPw === adminHash) {
    res.send(`
      <h1>Welcome Admin!</h1>
      <p>Your flag: ${challenges[1].flag}</p>
      <a href="/a02">Back</a> | <a href="/">Challenges</a>
    `);
  } else {
    res.send(`
      <h1>Login Failed</h1>
      <p>Invalid credentials.</p>
      <a href="/a02">Try Again</a>
    `);
  }
});

// ==================== Challenge 3: Injection (SQLi) ====================
const dbA03 = new sqlite3.Database(':memory:');
dbA03.serialize(() => {
  dbA03.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    email TEXT,
    role TEXT
  )`);

  const stmt = dbA03.prepare('INSERT INTO users (username, email, role) VALUES (?, ?, ?)');
  stmt.run('admin', 'admin@company.com', 'Administrator');
  stmt.run('user1', 'user1@company.com', 'Employee');
  stmt.run('user2', 'user2@company.com', 'Manager');
  stmt.run('flagholder', 'flag@secret.com', challenges[2].flag);
  stmt.finalize();
});

app.get('/a03', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Employee Directory</title></head><body>
      <h1>Employee Directory</h1>
      <p><a href="/">Back to Challenges</a></p>
      <form method="POST" action="/a03/search">
        <input type="text" name="q" placeholder="Search by username" required>
        <button type="submit">Search</button>
      </form>
    </body></html>
  `);
});

app.post('/a03/search', (req, res) => {
  const searchTerm = req.body.q;
  const query = `SELECT * FROM users WHERE username LIKE '%${searchTerm}%'`;
  console.log('Challenge 3 Query:', query);

  dbA03.all(query, (err, rows) => {
    if (err) {
      res.status(500).send('Database error: ' + err.message);
    } else {
      let results = '<h2>Search Results</h2><ul>';
      if (rows.length === 0) {
        results += '<li>No users found.</li>';
      } else {
        rows.forEach((row) => {
          results += `<li>ID: ${row.id} | Username: ${row.username} | Email: ${row.email} | Role: ${row.role}</li>`;
        });
      }
      results += '</ul>';
      res.send(`
        <!DOCTYPE html>
        <html><head><title>Employee Directory</title></head><body>
          <h1>Search Employees</h1>
          <p><a href="/a03">New Search</a> | <a href="/">Challenges</a></p>
          <form method="POST" action="/a03/search">
            <input type="text" name="q" placeholder="Search by username" required>
            <button type="submit">Search</button>
          </form>
          ${results}
        </body></html>
      `);
    }
  });
});

// ==================== Challenge 4: Insecure Design (Business Logic Flaw) ====================
let balance = 1000;

app.get('/a04', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Bank Transfer</title></head><body>
      <h1>Bank Transfer</h1>
      <p><a href="/">Back to Challenges</a></p>
      <p>Current Balance: $$  {balance}</p>
      <form method="POST" action="/a04/transfer">
        <input type="number" name="amount" placeholder="Amount to transfer (positive to add, negative to withdraw)" step="0.01">
        <button type="submit">Transfer</button>
      </form>
      <p>Hint: Design flaw allows over-withdrawal. Make balance <=0 for flag.</p>
    </body></html>
  `);
});

app.post('/a04/transfer', (req, res) => {
  const amount = parseFloat(req.body.amount) || 0;
  balance += amount;

  if (balance <= 0) {
    res.send(`
      <h1>Overdraft! Flag unlocked.</h1>
      <p>Flag: ${challenges[3].flag}</p>
      <p>New Balance:   $${balance}</p>
      <a href="/a04">Back</a>
    `);
  } else {
    res.send(`
      <h1>Transfer Successful</h1>
      <p>New Balance: $${balance}</p>
      <a href="/a04">Back</a>
    `);
  }
});

// ==================== Challenge 5: Security Misconfiguration (Default Creds) ====================
app.get('/a05', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Admin Panel</title></head><body>
      <h1>Admin Panel</h1>
      <p><a href="/">Back to Challenges</a></p>
      <p>Login with default credentials to access debug info.</p>
      <form method="POST" action="/a05/admin">
        <input type="text" name="user" placeholder="Username" required>
        <input type="password" name="pass" placeholder="Password" required>
        <button type="submit">Login</button>
      </form>
      <p>Hint: Defaults are often unchanged...</p>
    </body></html>
  `);
});

app.post('/a05/admin', (req, res) => {
  const { user, pass } = req.body;
  if (user === 'admin' && pass === 'admin') {
    res.send(`
      <h1>Admin Access Granted!</h1>
      <p>Debug Flag: ${challenges[4].flag}</p>
      <a href="/a05">Back</a>
    `);
  } else {
    res.send('<h1>Access Denied</h1><a href="/a05">Try Again</a>');
  }
});

// ==================== Challenge 6: Vulnerable Components (Prototype Pollution) ====================
function unsafeMerge(obj, payload) {
  for (let key in payload) {
    obj.__proto__[key] = payload[key];
  }
  return obj;
}

app.get('/a06', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Config Updater</title></head><body>
      <h1>Config Updater</h1>
      <p><a href="/">Back to Challenges</a></p>
      <form method="POST" action="/a06/update">
        <input type="text" name="payload" placeholder='JSON payload e.g. {"__proto__":{"admin":true}}' required>
        <button type="submit">Update Config</button>
      </form>
      <p>Current Config: <span id="config">{ "user": "guest" }</span></p>
      <script>
        fetch('/a06/config').then(r => r.json()).then(d => document.getElementById('config').textContent = JSON.stringify(d));
      </script>
    </body></html>
  `);
});

app.get('/a06/config', (req, res) => {
  res.json({ user: 'guest' });
});

app.post('/a06/update', (req, res) => {
  try {
    const payload = JSON.parse(req.body.payload);
    const config = unsafeMerge({}, payload);
    if (config.admin) {
      res.send(`
        <h1>Admin Config Set!</h1>
        <p>Flag: ${challenges[5].flag}</p>
        <a href="/a06">Back</a>
      `);
    } else {
      res.send('<h1>Update Failed</h1><a href="/a06">Back</a>');
    }
  } catch (e) {
    res.send('<h1>Invalid JSON</h1><a href="/a06">Back</a>');
  }
});

// ==================== Challenge 7: Auth Failures (Brute Force) ====================
app.get('/a07', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Secure Login</title></head><body>
      <h1>Secure Login</h1>
      <p><a href="/">Back to Challenges</a></p>
      <form method="POST" action="/a07/login">
        <input type="text" name="user" value="admin" readonly>
        <input type="password" name="pass" placeholder="Password (try brute force)" required>
        <button type="submit">Login</button>
      </form>
      <p>Hint: No rate limiting. Password is 'admin123'.</p>
    </body></html>
  `);
});

app.post('/a07/login', (req, res) => {
  const pass = req.body.pass;
  if (pass === 'admin123') {
    res.send(`
      <h1>Login Success!</h1>
      <p>Flag: ${challenges[6].flag}</p>
      <a href="/a07">Back</a>
    `);
  } else {
    res.send('<h1>Wrong Password</h1><a href="/a07">Try Again</a>');
  }
});

// ==================== Challenge 8: Integrity Failures (Unsafe YAML Deserialization) ====================
app.get('/a08', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Config Loader</title></head><body>
      <h1>Config Loader</h1>
      <p><a href="/">Back to Challenges</a></p>
      <form method="POST" action="/a08/load">
        <textarea name="yaml" placeholder="YAML payload e.g. flag: true" rows="5" cols="50"></textarea><br>
        <button type="submit">Load Config</button>
      </form>
      <p>Hint: Unsafe deserialization via YAML.</p>
    </body></html>
  `);
});

app.post('/a08/load', (req, res) => {
  try {
    const config = yaml.load(req.body.yaml, { loader: true });
    if (config && config.flag) {
      res.send(`<h1>Config Loaded!</h1><p>Flag: ${challenges[7].flag}</p><a href="/a08">Back</a>`);
    } else {
      res.send('<h1>Load Failed</h1><a href="/a08">Back</a>');
    }
  } catch (e) {
    res.send(`<h1>Error: ${e.message}</h1><a href="/a08">Back</a>`);
  }
});

// ==================== Challenge 9: Logging Failures (Replay Attack) ====================
let a09Transferred = false;

app.get('/a09', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Transfer System</title></head><body>
      <h1>Transfer System</h1>
      <p><a href="/">Back to Challenges</a></p>
      <form method="POST" action="/a09/action">
        <input type="hidden" name="transfer" value="initiate">
        <button type="submit">Initiate Transfer</button>
      </form>
      <p>Hint: Replay the POST request twice to bypass "one-time" check.</p>
    </body></html>
  `);
});

app.post('/a09/action', (req, res) => {
  if (req.body.transfer === 'initiate' && !a09Transferred) {
    a09Transferred = true;
    res.send('<h1>Transfer Initiated (one-time only?)</h1><a href="/a09">Back</a>');
  } else if (req.body.transfer === 'initiate' && a09Transferred) {
    res.send(`
      <h1>Transfer Succeeded on Replay!</h1>
      <p>Flag: ${challenges[8].flag}</p>
      <a href="/a09">Back</a>
    `);
    a09Transferred = false;
  } else {
    res.send('<h1>Invalid Action</h1><a href="/a09">Back</a>');
  }
});

// ==================== Challenge 10: SSRF ====================
app.get('/internal-flag', (req, res) => {
  res.send(challenges[9].flag);
});

app.get('/a10', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>URL Fetcher</title></head><body>
      <h1>URL Fetcher</h1>
      <p><a href="/">Back to Challenges</a></p>
      <form method="GET" action="/a10/fetch">
        <input type="url" name="url" placeholder="http://example.com" required>
        <button type="submit">Fetch</button>
      </form>
      <p>Hint: Try fetching internal resources like http://localhost:3000/internal-flag</p>
    </body></html>
  `);
});

app.get('/a10/fetch', async (req, res) => {
  const url = req.query.url;
  try {
    const response = await axios.get(url);
    if (response.data.includes('FLAG{')) {
      res.send(`
        <h1>Fetched Content:</h1>
        <p>${response.data}</p>
        <a href="/a10">Back</a>
      `);
    } else {
      res.send(`<h1>Content:</h1><p>${response.data.substring(0, 200)}...</p><a href="/a10">Back</a>`);
    }
  } catch (e) {
    res.send(`<h1>Error: ${e.message}</h1><a href="/a10">Back</a>`);
  }
});

app.listen(port, () => {
  console.log(`Web Security Challenges Hub running at http://localhost:${port}`);
});