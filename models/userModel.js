const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please add first name"],
    },
    email: {
      type: String,
      required: [true, "Please add last name"],
    },
    isVerified: { type: Boolean, default: false },

    password: {
      type: String,
      required: [true, "Please add a password"],
    },
    resetToken: String,
    expireToken: Date,
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", userSchema);
