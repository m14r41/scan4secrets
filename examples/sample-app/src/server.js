const cp = require('child_process');
app.get('/p', (req, res) => {
  res.send(`<h1>${req.query.q}</h1>`);                      // reflected XSS (CWE-79)
  db.query(`SELECT * FROM u WHERE id = ${req.params.id}`);  // SQL injection (CWE-89)
  cp.exec('convert ' + req.query.file);                     // command injection (CWE-78)
  res.redirect(req.query.next);                             // open redirect (CWE-601)
});
