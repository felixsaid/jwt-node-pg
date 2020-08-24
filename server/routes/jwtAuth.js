const router = require("express").Router();
const pool = require("../src/db");
const bcrypt = require("bcrypt");
const jwtGenerator = require("../utils/jwtGenerator");
const validInfo = require("../middleware/validInfo");
const authorization = require("../middleware/authorization");

//user register

router.post("/register", validInfo, async (req, res) => {
  try {
    //1. destructure the req.body (name, email, password)

    const { name, email, password } = req.body;

    //2. check if user exists (if exists throw error)

    const user = await pool.query("SELECT * FROM users WHERE user_email = $1", [
      email,
    ]);

    if (user.rows.length !== 0) {
      res.status(401).send(`User with email ${email} already exists!`);
    }

    //3. bcrypt the user password

    const saltRound = 10;
    const salt = await bcrypt.genSalt(saltRound);

    const bcryptPassword = await bcrypt.hash(password, salt);

    //4. send the user to the database

    const newUser = await pool.query(
      "INSERT INTO users(user_name, user_email, user_password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, bcryptPassword]
    );

    //res.status(200).send(newUser.rows[0]);
    //5. generate jwt token

    const token = jwtGenerator(newUser.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

//user login route

router.post("/login", validInfo, async (req, res) => {
  try {
    //1. detructure req.body

    const { email, password } = req.body;

    //2. check if user exist(if use doesnt exist throw error)

    const user = await pool.query("SELECT * FROM users WHERE user_email = $1", [
      email,
    ]);

    if (user.rows.length === 0) {
      res.status(401).json("Email or password is incorrect");
    }
    //3. check if password provided matches password in the database

    const validPassword = await bcrypt.compare(
      password,
      user.rows[0].user_password
    );

    if (!validPassword) {
      res.status(401).json("Email or password is incorrect");
    }

    //4. give the token

    const token = jwtGenerator(user.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

router.get("/is-verify", authorization, async (req, res) => {
  try {
    res.json(true);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

module.exports = router;
