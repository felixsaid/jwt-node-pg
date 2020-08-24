const Pool = require("pg").Pool;

const pool = new Pool({
  user: "postgres",
  password: "root",
  database: "jwtdb",
  host: "localhost",
  port: 5432,
});

module.exports = pool;
