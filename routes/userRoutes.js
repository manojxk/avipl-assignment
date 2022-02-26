const express = require("express");
const router = express.Router();
const { registerUser, loginUser } = require("../controllers/userController");
const { protect } = require("../middleware/authMiddleware");

//Signup
router.post("/", registerUser);
//Login
router.post("/login", loginUser);
//Fetch User List
