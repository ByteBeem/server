const cluster = require("cluster");
const http = require("http");
const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const csrf = require("csurf");
const csrfProtection = csrf({ cookie: true });
const hpp = require('hpp');
const nodemailer=require("nodemailer");
const axios=require("axios");
const saltRounds = 12;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const app = express();
const port = process.env.PORT || 3000;
const user = process.env.user;
const password = process.env.password;
const host = process.env.host;

app.use(bodyParser.json());
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(hpp());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));



app.set('trust proxy', 'loopback');

app.use(cors({
  origin: 'https://spinz-three.vercel.app',
  credentials: true,
  exposedHeaders: ['Content-Length', 'X-Content-Type-Options', 'X-Frame-Options'],
}));

// MySQL configuration with connection pool
const pool = mysql.createPool({
  host: host,
  user: user,
  password: password,
  database: "Spinz",
  port: 10023,
  connectionLimit: 20,
});

const secretKey = process.env.secret_key || "DonaldMxolisiRSA04?????";

// Set security headers
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "deny");
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Set CORS headers
  res.header('Access-Control-Allow-Origin', 'https://spinz-three.vercel.app');
  res.header('Access-Control-Allow-Credentials', true);

  next();
});

app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post("/deposit", async (req, res) => {
  try {
    console.log("hello");
    const { amount } = req.body;
    const amountValue = parseFloat(amount) * 100;
    console.log(amountValue);
    const token = req.header("Authorization").replace("Bearer ", "");
    const paymentData = {
      amount: amountValue,
      currency: "ZAR",
      cancelUrl: "https://spinz-three.vercel.app/deposit",
      successUrl: "https://spinz-three.vercel.app/profile",
      failureUrl: "https://spinz-three.vercel.app/dashboard",
    };

    const paymentUrl = "https://payments.yoco.com/api/checkouts/";

    const decodedToken = jwt.verify(token, secretKey);
    const userId = decodedToken.userId;

    const payfastResponse = await axios.post(
      paymentUrl,
      paymentData,
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer sk_live_15431d914BDxBGa7af8461190a33`,
        },
      }
    );

    if (payfastResponse.status === 200) {
      const { redirectUrl, data } = payfastResponse.data;
      console.log(payfastResponse.data);

      // Send email after successful payment initiation
      sendDepositConfirmationEmail(userId, amount);

      const paymentId = payfastResponse.data.id;
      console.log("paymentid", paymentId);
      console.log("userid", userId);
      console.log("amountvalue", amountValue);

      // Insert the payment details into the 'deposits' table
      const insertQuery =
        "INSERT INTO deposits (user_id, payment_id, amount) VALUES (?, ?, ?) ";
      const insertValues = [userId, paymentId, amountValue / 100];

      const results = await pool.query(insertQuery, insertValues);
      console.log("Deposit successfully inserted:", results);

      res.status(200).send({
        success: true,
        redirectUrl: redirectUrl,
      });
    } else {
      console.error(
        "Payment initiation failed. PayFast returned:",
        payfastResponse.status,
        payfastResponse.statusText,
        payfastResponse.data
      );
      res.status(500).send({
        success: false,
        error: "Payment initiation failed. PayFast returned an unexpected status.",
      });
    }
  } catch (error) {
    console.error("Payment initiation failed:", error);
    res.status(500).send({
      success: false,
      error: "Payment initiation failed. Internal server error.",
    });
  }
});

// Use body-parser middleware to parse raw request bodies
app.use(bodyParser.text({ type: 'text/*' }));

app.post("/spinz/webhook/spinz", async function(req, res) {
  const { type, payload } = req.body;

  if (type === 'payment.succeeded') {
    const { metadata } = payload;
    if (metadata && metadata.checkoutId) {
      const checkoutId = metadata.checkoutId;

      try {
        // Query the deposits table to get the user_id and amount
        pool.query('SELECT user_id, amount FROM deposits WHERE payment_id = ?', [checkoutId], (error, results) => {
          if (error) {
            console.error('Error querying database:', error);
            res.sendStatus(500);
            return;
          }

          if (results.length > 0) {
            const { user_id, amount } = results[0];
            const latestAmount = parseFloat(amount);

            // Fetch the current balance from the users table
            pool.query('SELECT balance FROM users WHERE id = ?', [user_id], (fetchError, fetchResults) => {
              if (fetchError) {
                console.error('Error fetching user balance:', fetchError);
                res.sendStatus(500);
                return;
              }

              if (fetchResults.length > 0) {
                const userBalance = parseFloat(fetchResults[0].balance);

                // Log the values for debugging
                console.log(`user_id: ${user_id}, latestAmount: ${latestAmount}, userBalance: ${userBalance}`);

                // Update the users table with the new balance
                const newBalance = parseFloat(userBalance + latestAmount);
                
                // Log the new balance for debugging
                console.log(`newBalance: ${newBalance}`);

                pool.query('UPDATE users SET balance = ? WHERE id = ?', [newBalance, user_id], (updateError) => {
                  if (updateError) {
                    console.error('Error updating user balance:', updateError);
                    res.sendStatus(500);
                    return;
                  }

                  console.log(`User ${user_id} updated with a balance of $${newBalance}.`);
                  res.sendStatus(200);
                });
              } else {
                console.error(`User not found for user_id: ${user_id}`);
                res.sendStatus(404);
              }
            });
          } else {
            console.error(`Deposit not found for checkoutId: ${checkoutId}`);
            res.sendStatus(404);
          }
        });
      } catch (error) {
        console.error('Error processing payment webhook:', error);
        res.sendStatus(500);
      }
    } else {
      console.error('Metadata or checkoutId not found in the payload.');
      res.sendStatus(400);
    }
  } else {
    console.log(`Webhook type ${type} not supported.`);
    res.sendStatus(200);
  }
});


// Function to send deposit confirmation email
function sendDepositConfirmationEmail(userId, amount) {
  const transporter = nodemailer.createTransport({
    // Configure your mail server here
    service: 'Gmail',
    auth: {
      user: 'heckyl66@gmail.com',
      pass: 'wvzqobuvijaribkb',
    },
  });

  const mailOptions = {
    from: "heckyl66@gmail.com",
    to: "donald.mxolisi@proton.me", 
    subject: "Deposit Confirmation",
    html: `
      <p>Deposit Confirmation Details:</p>
      <ul>
        <li>User ID: ${userId}</li>
        <li>Deposit Amount: ${amount}</li>
      </ul>
      <p>Your deposit request is being processed. Thank you!</p>
    `,
  };

  transporter.sendMail(mailOptions, (emailError, info) => {
    if (emailError) {
      console.error("Error sending email:", emailError);
      // Handle the email sending error
    } else {
      console.log("Email sent: " + info.response);
      // You might want to log or handle the successful email sending
    }
  });
}

// Signup endpoint
app.post("/signup", async (req, res) => {
  const { fullName, surname, cell, idNumber, password } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res
      .status(409)
      .json({ error: "Invalid input. Please check your information." });
  }

  if (!fullName || !surname || !cell || !idNumber || !password) {
    return res.status(409).json({ error: "All fields are required." });
  }

  try {
    const [checkCellResults] = await pool.query("SELECT * FROM users WHERE cell = ?", [cell]);

    if (checkCellResults.length > 0) {
      return res.status(201).json({ error: "Cell number already registered." });
    }

    const [checkIdNumberResults] = await pool.query("SELECT * FROM users WHERE idNumber = ?", [idNumber]);

    if (checkIdNumberResults.length > 0) {
      return res.status(208).json({ error: "ID number already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const insertQuery =
      "INSERT INTO users (name, surname, idNumber, cell, password, balance) VALUES (?, ?, ?, ?, ?, ?)";
    const insertValues = [fullName, surname, idNumber, cell, hashedPassword, 25.0];

    await pool.query(insertQuery, insertValues);

    res.status(200).json({ message: "User created successfully." });
  } catch (err) {
    console.error("Error during signup:", err);
    return res
      .status(500)
      .json({ error: "Internal server error. Please try again later." });
  }
});

// Login endpoint
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP, please try again later",
});

app.post("/login",  loginLimiter, async (req, res) => {
  const { cell, password, token } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res
      .status(400)
      .json({ error: "Invalid input. Please check your data." });
  }

  try {
    if (token) {
      let decodedToken;
      try {
        decodedToken = jwt.verify(token, secretKey);
      } catch (err) {
        if (err.name === "TokenExpiredError") {
          const userId = decodedToken.userId;
          const [results] = await pool.query("SELECT * FROM users WHERE id = ?", [userId]);

          if (results.length === 0) {
            return res.status(401).json({ error: "User not found." });
          }

          const user = results[0];

          const newToken = jwt.sign(
            {
              userId: user.id,
              id: user.id,
              name: user.name,
              cell: user.cell,
              balance: user.balance,
              surname: user.surname,
            },
            secretKey,
            { expiresIn: "7D" }
          );

          return res.status(200).json({ token: newToken });
        } else {
          return res.status(401).json({ error: "Token is invalid or expired." });
        }
      }

      const userId = decodedToken.userId;
      const [results] = await pool.query("SELECT * FROM users WHERE id = ?", [userId]);

      if (results.length === 0) {
        return res.status(401).json({ error: "User not found." });
      }

      const user = results[0];
      const userData = {
        id: user.id,
        name: user.name,
        cell: user.cell,
        balance: user.balance,
        // Include other necessary fields
      };

      return res.status(200).json({ userData });
    } else {
      const [results] = await pool.query("SELECT * FROM users WHERE cell = ?", [cell]);

      if (results.length === 0) {
        return res.status(201).json({ error: "Incorrect cellphone." });
      }

      const user = results[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(202).json({ error: "Incorrect password." });
      }

      const newToken = jwt.sign(
        {
          userId: user.id,
          id: user.id,
          name: user.name,
          cell: user.cell,
          balance: user.balance,
          surname: user.surname,
        },
        secretKey,
        { expiresIn: "7D" }
      );

      const userData = {
        id: user.id,
        name: user.name,
        cell: user.cell,
        balance: user.balance,
        surname: user.surname,
      };

      res.status(200).json({ token: newToken, Data: userData });
    }
  } catch (err) {
    console.error("Error during login:", err);
    return res
      .status(500)
      .json({ error: "Internal server error. Please try again later." });
  }
});

const server = http.createServer(app);

if (cluster.isMaster) {
  const numCPUs = require("os").cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
  });
} else {
  server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}
