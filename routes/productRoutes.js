const express = require("express");
const router = express.Router();
const {
  getProducts,
  setProducts,
} = require("../controllers/productController");

const { protect } = require("../middleware/authMiddleware");

router.route("/").get(protect, getProducts).post(protect, setProducts);

module.exports = router;
