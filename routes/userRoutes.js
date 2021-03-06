const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  resetPasswordMail,
  resetPassword,
  confirmEmail,
} = require("../controllers/userController");
const { protect } = require("../middleware/authMiddleware");

//Signup
router.post("/", registerUser);
//Login
router.post("/login", loginUser);
//reset password
router.post("/reset", resetPasswordMail);
router.post("/reset/:token", resetPassword);
router.post("/confirmation/:email/:token", confirmEmail);

module.exports = router;
