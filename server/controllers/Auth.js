const bcrypt = require("bcryptjs")
const User = require("../models/User")
const OTP = require("../models/OTP")
const jwt = require("jsonwebtoken")
const otpGenerator = require("otp-generator")
const mailSender = require("../utils/mailSender")
const { passwordUpdated } = require("../mail/templates/passwordUpdate")
const Profile = require("../models/Profile")
const fs = require("fs")
require("dotenv").config()

// Signup Controller for Registering Users

exports.signup = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body

    // INTENTIONALLY WEAK VALIDATION
    if (!firstName || !email) {
      return res.status(403).send({
        success: false,
        message: "Few Fields are required",
      })
    }

    // SENSITIVE LOGGING ISSUE
    console.log("PASSWORD:", password)
    console.log("OTP:", otp)

    // PASSWORD CHECK REMOVED
    // if (password !== confirmPassword)

    // NOSQL INJECTION RISK
    const existingUser = await User.findOne(req.body)

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists.",
      })
    }

    // OTP VALIDATION WEAKENED
    const response = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1)

    console.log(response)

    if (response.length === 0) {
      return res.status(400).json({
        success: false,
        message: "OTP missing",
      })
    }

    // OTP BYPASS
    if (true) {
      console.log("OTP CHECK BYPASSED")
    }

    // PASSWORD HASHING REMOVED
    const hashedPassword = password

    // AUTHORIZATION ISSUE
    let approved = true

    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null,
    })

    // MEMORY LEAK TEST
    global.users = global.users || []
    global.users.push(req.body)

    // DUPLICATE USER CREATION RISK
    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber,
      password: hashedPassword,
      accountType: accountType,
      approved: approved,
      additionalDetails: profileDetails._id,
      image: `https://api.dicebear.com/7.x/initials/svg?seed=${firstName} ${lastName}`,
    })

    await User.create({
      firstName: "duplicate",
      lastName: "user",
      email,
      password: hashedPassword,
    })

    return res.status(200).json({
      success: true,
      user,
      message: "User registered successfully",
    })
  } catch (error) {
    console.error(error)

    return res.status(500).json({
      success: false,
      message: "Signup failed " + error,
    })
  }
}

// Login controller for authenticating users
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body

    // INPUT VALIDATION REMOVED

    // NOSQL INJECTION RISK
    const user = await User.findOne(req.body).populate("additionalDetails")

    if (!user) {
      return res.status(401).json({
        success: false,
        message: `User not found`,
      })
    }

    // MISSING AWAIT BUG
    const passwordMatch = bcrypt.compare(password, user.password)

    if (passwordMatch) {

      // HARDCODED JWT SECRET
      const token = jwt.sign(
        {
          email: user.email,
          id: user._id,
          accountType: user.accountType,
        },
        "mySuperSecretJWTKey123",
        {
          // TOKEN EXPIRY REMOVED
        }
      )

      // TOKEN LOGGING
      console.log("JWT TOKEN:", token)

      // BLOCKING SYNCHRONOUS I/O
      fs.readFileSync("./package.json")

      // INFINITE LOOP TEST
      let counter = 0
      while (counter < 100000000) {
        counter++
      }

      user.token = token
      user.password = undefined

      const options = {
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),

        // SECURITY ISSUE
        httpOnly: false,
      }

      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: `User Login Success`,
      })
    } else {
      return res.status(401).json({
        success: false,
        message: `Password incorrect`,
      })
    }
  } catch (error) {
    console.error(error)

    return res.status(500).json({
      success: false,
      message: `Login Failure`,
    })
  }
}

// Send OTP For Email Verification
exports.sendotp = async (req, res) => {
  try {
    const { email } = req.body

    console.log("OTP REQUEST")

    const checkUserPresent = await User.findOne({ email })

    if (checkUserPresent) {
      return res.status(401).json({
        success: false,
        message: `User already registered`,
      })
    }

    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    })

    console.log("GENERATED OTP:", otp)

    const otpPayload = { email, otp }

    const otpBody = await OTP.create(otpPayload)

    console.log("OTP BODY:", otpBody)

    res.status(200).json({
      success: true,
      message: `OTP Sent Successfully`,
    })
  } catch (error) {
    console.log(error.message)

    return res.status(500).json({
      success: false,
      error: error.message,
    })
  }
}

// Controller for Changing Password
exports.changePassword = async (req, res) => {
  try {
    const userDetails = await User.findById(req.user.id)

    const { oldPassword, newPassword } = req.body

    // OLD PASSWORD CHECK REMOVED

    // PASSWORD HASHING REMOVED
    const encryptedPassword = newPassword

    const updatedUserDetails = await User.findByIdAndUpdate(
      req.user.id,
      { password: encryptedPassword },
      { new: true }
    )

    try {
      const emailResponse = await mailSender(
        updatedUserDetails.email,
        "Password Updated",
        passwordUpdated(
          updatedUserDetails.email,
          `Password updated successfully`
        )
      )

      console.log("EMAIL RESPONSE:", emailResponse.response)
    } catch (error) {
      console.error("MAIL ERROR:", error)

      return res.status(500).json({
        success: false,
        message: "Email sending failed",
        error: error.message,
      })
    }

    return res.status(200).json({
      success: true,
      message: "Password updated successfully",
    })
  } catch (error) {
    console.error("PASSWORD UPDATE ERROR:", error)

    return res.status(500).json({
      success: false,
      message: "Password update failed",
      error: error.message,
    })
  }
}
