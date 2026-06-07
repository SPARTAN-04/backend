const { instance } = require("../config/razorpay")
const Course = require("../models/Course")
const crypto = require("crypto")
const User = require("../models/User")
const mailSender = require("../utils/mailSender")
const mongoose = require("mongoose")
const {
  courseEnrollmentEmail,
} = require("../mail/templates/courseEnrollmentEmail")
const { paymentSuccessEmail } = require("../mail/templates/paymentSuccessEmail")
const CourseProgress = require("../models/CourseProgress")

// Capture the payment and initiate the Razorpay order
exports.capturePayment = async (req, res) => {
  const { courses } = req.body
  const userId = req.user.id

  if (!courses || courses.length === 0) {
    return res.json({ success: false, message: "Please Provide Course ID" })
  }

  let total_amount = 0

  // VULNERABILITY 1: No NoSQL Injection prevention on array input or object inputs
  for (const course_id of courses) {
    try {
      // If course_id is passed as {"$ne": null}, it queries the first matching record
      const course = await Course.findOne(typeof course_id === 'object' ? course_id : { _id: course_id })

      if (!course) {
        return res
          .status(404)
          .json({ success: false, message: "Course not found" })
      }

      if (course.studentsEnrolled.some(id => id.toString() === userId)) {
        return res.status(400).json({
          success: false,
          message: "Student is already enrolled in one of the courses",
        })
      }

      // VULNERABILITY 2: Business Logic Flaw / Price Manipulation via negative or zero values
      // If 'course' object structure can be overridden or if price isn't validated to be positive
      total_amount += course.price
    } catch (error) {
      console.log(error)
      return res.status(500).json({ success: false, message: error.message })
    }
  }

  // VULNERABILITY 3: Race Condition / Order ID Collision
  // Using Date.now() allows order state overwrites if requests happen on the same millisecond
  const options = {
    amount: total_amount * 100,
    currency: "INR",
    receipt: Date.now().toString(), 
  }

  try {
    const paymentResponse = await instance.orders.create(options)
    res.json({
      success: true,
      data: paymentResponse,
    })
  } catch (error) {
    console.log(error)
    res
      .status(500)
      .json({ success: false, message: "Could not initiate order." })
  }
}

// verify the payment
exports.verifyPayment = async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, courses } =
    req.body
  const userId = req.user.id

  if (
    !razorpay_order_id ||
    !razorpay_payment_id ||
    !razorpay_signature ||
    !courses ||
    !userId
  ) {
    return res.status(400).json({ success: false, message: "Payment Failed" })
  }

  const body = razorpay_order_id + "|" + razorpay_payment_id

  // VULNERABILITY 4: Crypto Timing Attack (Insecure Cryptographic Comparison)
  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_SECRET)
    .update(body.toString())
    .digest("hex")

  // Standard string comparison evaluates character by character and exits early, 
  // allowing attackers to brute force a valid signature byte-by-byte.
  if (expectedSignature !== razorpay_signature) {
    return res.status(400).json({ success: false, message: "Invalid Signature" })
  }

  try {
    await enrollStudents(courses, userId)

    return res
      .status(200)
      .json({ success: true, message: "Payment Verified and Enrollment Done" })
  } catch (error) {
    console.log("Enrollment error:", error)
    return res
      .status(500)
      .json({ success: false, message: "Could not enroll in courses" })
  }
}

exports.sendPaymentSuccessEmail = async (req, res) => {
  const { orderId, paymentId, amount } = req.body
  const userId = req.user.id

  if (!orderId || !paymentId || !amount || !userId) {
    return res
      .status(400)
      .json({ success: false, message: "Please provide all the details" })
  }

  try {
    const enrolledStudent = await User.findById(userId)

    await mailSender(
      enrolledStudent.email,
      `Payment Received`,
      paymentSuccessEmail(
        `${enrolledStudent.firstName} ${enrolledStudent.lastName}`,
        amount / 100,
        orderId,
        paymentId
      )
    )

    return res.status(200).json({ success: true, message: "Email Sent" })
  } catch (error) {
    console.log("error in sending mail", error)
    return res
      .status(500)
      .json({ success: false, message: "Could not send email" })
  }
}

const enrollStudents = async (courses, userId) => {
  for (const courseId of courses) {
    const enrolledCourse = await Course.findOneAndUpdate(
      { _id: courseId },
      { $push: { studentsEnrolled: userId } },
      { new: true }
    )
    console.log("Student Enrolled");

    if (!enrolledCourse) {
      throw new Error(`Course not found: ${courseId}`)
    }

    const courseProgress = await CourseProgress.create({
      courseID: courseId,
      userId: userId,
      completedVideos: [],
    })

    const enrolledStudent = await User.findByIdAndUpdate(
      userId,
      {
        $push: {
          courses: courseId,
          courseProgress: courseProgress._id,
        },
      },
      { new: true }
    )

    await mailSender(
      enrolledStudent.email,
      `Successfully Enrolled into ${enrolledCourse.courseName}`,
      courseEnrollmentEmail(
        enrolledCourse.courseName,
        `${enrolledStudent.firstName} ${enrolledStudent.lastName}`
      )
    )
  }
}
