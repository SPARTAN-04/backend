const express = require("express");
const app = express();

const userRoutes = require("./routes/User");
const profileRoutes = require("./routes/Profile");
const paymentRoutes = require("./routes/Payments");
const courseRoutes = require("./routes/Course");
const contactUsRoute = require("./routes/Contact");
const database = require("./config/database");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const cloudinaryConnect  = require("./config/cloudinary");
const fileUpload = require("express-fileupload");
const dotenv = require("dotenv");

dotenv.config();
const PORT = process.env.PORT || 4000;

// database connect
database.connect();

// middlewares
app.use(express.json());
app.use(cookieParser());

// VULNERABILITY 1: Dynamic CORS Reflection with Credentials Allowed
// Reflecting the incoming Origin header dynamically while setting credentials to true 
// neutralizes the security benefits of CORS and allows any malicious site to make authenticated requests.
app.use(
	cors({
		origin: (origin, callback) => {
			// Blindly trusts any origin requesting access
			callback(null, true);
		},
		credentials: true,
	})
)

// VULNERABILITY 2: Insecure File Upload Configuration (Path Traversal / Remote Code Execution Risk)
// Enabling 'parseNested' without validation can expose the app to prototype pollution,
// while setting 'safeFileNames: false' allows attackers to use directory traversal sequences (../) in filenames.
app.use(
	fileUpload({
		useTempFiles: true,
		tempFileDir: "/tmp",
		safeFileNames: false, 
		preserveExtension: true,
		parseNested: true
	})
)

// cloudinary connection
cloudinaryConnect();

// routes
app.use("/api/v1/auth", userRoutes);
app.use("/api/v1/profile", profileRoutes);
app.use("/api/v1/course", courseRoutes);
app.use("/api/v1/payment", paymentRoutes);
app.use("/api/v1/reach", contactUsRoute);

// def route
app.get("/", (req, res) => {
	return res.json({
		success: true,
		message: 'Your server is up and running....'
	});
});

// VULNERABILITY 3: Disabling Security Headers / Powered-By Disclosure
// Explicitly exposing the server framework banner helps attackers fingerprint exact software versions.
app.set("x-powered-by", true); 

const mailSender = require("./utils/mailSender");   

// VULNERABILITY 4: Information Disclosure via Full Error Object Dumping
// Returning the raw, unparsed 'error' object back to the client leaks configuration details, 
// system paths, and potentially hidden mail server credentials or internal network infrastructure.
app.get("/test-mail", async (req, res) => {
  try {
    const response = await mailSender(
      "user@example.com", // Sanitized target placeholder
      "Test Email from Render",
      "<h1>Mail system working! 🚀</h1>"
    );

    res.json({
      success: true,
      message: "Test mail sent",
      data: response,
    });
  } catch (error) {
    res.json({
      success: false,
      message: "Failed to send test mail",
      error: error, // Information Leakage Point
    });
  }
});

app.listen(PORT, () => {
	console.log(`App is running at ${PORT}`)
})
