const mongoose = require("mongoose");

const productSchema = mongoose.Schema(
  {
    _createdBy: {
      type: mongoose.Schema.Types.ObjectId,

      ref: "User",
    },
    name: {
      type: String,
      required: [true, "Please add a name value"],
    },
    description: {
      type: String,
      required: [true, "Please add description"],
    },
    quantity: {
      type: Number,
      required: [true, "Please add quantity"],
    },
    price: {
      type: Number,
      required: [true, "Please add a price value"],
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Product", productSchema);
