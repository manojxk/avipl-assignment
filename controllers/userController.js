const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const Token = require("../models/tokenModel");

const nodemailer = require("nodemailer");
const sendgridTransport = require("nodemailer-sendgrid-transport");
const crypto = require("crypto");
const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key: process.env.SENDGRID_API,
    },
  })
);

// @desc    Register new user
// @route   POST /api/users
// @access  Public
const confirmEmail = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please add all fields");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create user
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  if (user) {
    const token = await Token.create({
      _userId: user._id,
      token: crypto.randomBytes(16).toString("hex"),
    });

    let mailOptions = {
      from: "sdemanojkumar@gmail.com",
      to: user.email,
      subject: "Account Verification Link",
      text:
        "Hello " +
        req.body.name +
        ",\n\n" +
        "Please verify your account by clicking the link: \nhttp://" +
        req.headers.host +
        "/confirmation/" +
        user.email +
        "/" +
        token.token +
        "\n\nThank You!\n",
    };

    transporter.sendMail(mailOptions, function (err) {
      if (err) {
        return res.status(500).send({
          msg: "Technical Issue!, Please click on resend for verify your Email.",
        });
      }
      return res
        .status(200)
        .send(
          "A verification email has been sent to " +
            user.email +
            ". It will be expire after one day."
        );
    });
  } else {
    res.status(400);
    throw new Error("Try again");
  }
});

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please add all fields");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create user
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  if (user) {
    const token = await Token.create({
      _userId: user._id,
      token: crypto.randomBytes(16).toString("hex"),
    });

    let mailOptions = {
      from: "sdemanojkumar@gmail.com",
      to: user.email,
      subject: "Account Verification Link",
      text:
        "Hello " +
        req.body.name +
        ",\n\n" +
        "Please verify your account by clicking the link: \nhttp://" +
        req.headers.host +
        "/confirmation/" +
        user.email +
        "/" +
        token.token +
        "\n\nThank You!\n",
    };

    transporter.sendMail(mailOptions, function (err) {
      if (err) {
        return res.status(500).send({
          msg: "Technical Issue!, Please click on resend for verify your Email.",
        });
      }
      return res
        .status(200)
        .send(
          "A verification email has been sent to " +
            user.email +
            ". It will be expire after one day."
        );
    });
  } else {
    res.status(400);
    throw new Error("Try again");
  }
});

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Check for user email
  const user = await User.findOne({ email });

  if (user && (await bcrypt.compare(password, user.password))) {
    if (!user.isVerified) {
      return res.status(401).send({
        msg: "Your Email has not been verified. Please click on resend",
      });
    }
    res.json({
      _id: user.id,
      email: user.email,

      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error("Invalid credentials");
  }
});

const resetPasswordMail = asyncHandler(async (req, res) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email }).then((user) => {
      if (!user) {
        return res
          .status(422)
          .json({ error: "User doesn't exists with this email" });
      }
      user.resetToken = token;
      user.expireToken = Date.now() + 3600000;
      user.save().then((result) => {
        transporter.sendMail({
          to: user.email,
          from: "sdemanojkumar@gmail.com",
          subject: "password reset",
          html: `
                  <p>You requested for password reset</p>
                  <h5>click on this <a href="http://localhost:5000/api/users/reset/${token}">link</a> to reset password</h5>
                  `,
        });
        res.json({ message: "Check your email" });
      });
    });
  });
});

const resetPassword = asyncHandler(async (req, res) => {
  const newPassword = req.body.password;
  const sentToken = req.params.token;
  User.findOne({ resetToken: sentToken, expireToken: { $gt: Date.now() } })
    .then((user) => {
      if (!user) {
        return res.status(422).json({ error: "Try again session expired" });
      }
      bcrypt.hash(newPassword, 12).then((hashedpassword) => {
        user.password = hashedpassword;
        user.resetToken = undefined;
        user.expireToken = undefined;
        user.save().then((saveduser) => {
          res.json({ message: "password updated success" });
        });
      });
    })
    .catch((err) => {
      console.log(err);
    });
});

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

module.exports = {
  registerUser,
  loginUser,
  resetPasswordMail,
  resetPassword,
};
