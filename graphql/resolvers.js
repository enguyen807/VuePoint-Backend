const bcrypt = require("bcryptjs");
const validator = require("validator");
const jwt = require("jsonwebtoken");

const nodemailer = require("nodemailer");
const sendgridTransport = require("nodemailer-sendgrid-transport");

const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key: `${process.env.SENDGRID_API_KEY}`,
    },
  })
);

const User = require("../models/user");
const { clearImage } = require("../util/file");

module.exports = {
  createUser: async function ({ userInput }, req) {
    //   const email = args.userInput.email;
    const errors = [];
    if (!validator.isEmail(userInput.email)) {
      errors.push({ message: "E-Mail is invalid." });
    }
    if (validator.isEmpty(userInput.name)) {
      errors.push({ message: "First name and last name must not be empty." });
    }
    if (validator.isEmpty(userInput.country)) {
      errors.push({ message: "Country must not be empty." });
    }
    if (
      validator.isEmpty(userInput.password) ||
      !validator.isLength(userInput.password, { min: 6 })
    ) {
      errors.push({ message: "Password too short!" });
    }
    if (errors.length > 0) {
      const error = new Error("Invalid input.");
      error.data = errors;
      error.code = 422;
      throw error;
    }
    const existingUser = await User.findOne({ email: userInput.email });
    if (existingUser) {
      const error = new Error("User exists already!");
      throw error;
    }
    const hashedPw = await bcrypt.hash(userInput.password, 12);
    const user = new User({
      email: userInput.email,
      name: userInput.name,
      password: hashedPw,
      country: userInput.country,
    });
    const createdUser = await user.save();

    // await this.verifyEmail(createdUser);

    return { ...createdUser._doc, _id: createdUser._id.toString() };
  },
  login: async function ({ email, password }) {
    const user = await User.findOne({ email: email });
    if (!user) {
      const error = new Error("User not found.");
      error.code = 401;
      throw error;
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      const error = new Error("Password is incorrect.");
      error.code = 401;
      throw error;
    }
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        email: user.email,
      },
      `${process.env.TOKEN_SECRET}`,
      { expiresIn: "1h" }
    );
    return {
      token: token,
      userId: user._id.toString(),
      isVerified: user.isVerified,
      isAdmin: user.isAdmin,
    };
  },
  verifyEmail: async function (user) {
    jwt.sign(
      { userId: user._id.toString(), email: user.email },
      `${process.env.EMAIL_SECRET}`,
      { expiresIn: "1d" },
      (err, emailToken) => {
        const url = `http://localhost:3000/confirmation/${emailToken}`;

        transporter.sendMail({
          to: user.email,
          from: "vuepoint@gmail.com",
          subject: "Signup succeeded",
          html: `Please click this email to confirm your email: <a href="${url}">${url}</a>`,
        });
      }
    );
  },
};
