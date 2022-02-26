const asyncHandler = require("express-async-handler");
const csvtojson = require("csvtojson");

const Product = require("../models/productModel");
const User = require("../models/userModel");

// @desc    Get products
// @route   GET /api/products
// @access  Private
const getProducts = asyncHandler(async (req, res) => {
  const products = await Product.find();

  res.status(200).json(products);
});

// @desc    Set products
// @route   POST /api/products
// @access  Private

const setProducts = asyncHandler(async (req, res) => {
  const fileName = `${__dirname}/sample.csv`;
  let arrayToInsert = [];
  csvtojson()
    .fromFile(fileName)
    .then((source) => {
      // Fetching the all data from each row
      for (let i = 0; i < source.length; i++) {
        let oneRow = {
          name: source[i]["name"],
          description: source[i]["description"],
          quantity: source[i]["quantity"],
          price: source[i]["price"],
          _createdBy: req.user.id,
        };
        arrayToInsert.push(oneRow);
      }
      // Function call
      Product.insertMany(arrayToInsert)
        .then(function () {
          res.status(200).send("Data inserted");
        })
        .catch(function (error) {
          console.log(error); // Failure
        });
    })
    .catch((error) => {
      console.error(error.message);
    });
});

module.exports = {
  getProducts,

  setProducts,
};
