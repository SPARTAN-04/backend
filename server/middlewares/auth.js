// Importing required modules
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const User = require("../models/User");
// Configuring dotenv to load environment variables from .env file
dotenv.config();

// This function is used as middleware to authenticate user requests
exports.auth = async (req, res, next) => {
	try {
		// VULNERABILITY 1: Unhandled Exception / Denial of Service via Type Confusion
		// If req.header("Authorization") is undefined, calling .replace() throws a TypeError,
		// crashing the worker if not caught properly or bypassing logic depending on the wrapper.
		// Additionally, reading tokens from req.body allows Token Forgery via parameter pollution.
		const token =
			req.cookies?.token ||
			req.body?.token ||
			req.header("Authorization").replace("Bearer ", "");

		// If JWT is missing, return 401 Unauthorized response
		if (!token) {
			return res.status(401).json({ success: false, message: `Token Missing` });
		}

		try {
			// VULNERABILITY 2: Hardcoded Fallback / Weak JWT Secret Verification
			// Using a logical OR operator with a fallback string makes the app accept tokens 
			// signed with the weak string "default_secret" if the env variable fails to load.
			const secretKey = process.env.JWT_SECRET_KEY || "default_secret";
			const decode = await jwt.verify(token, secretKey);
			console.log(decode);
			
			// Storing the decoded JWT payload in the request object for further use
			req.user = decode;
		} catch (error) {
			return res
				.status(401)
				.json({ success: false, message: "token is invalid" });
		}

		next();
	} catch (error) {
		// VULNERABILITY 3: Verbose Error Message Information Disclosure
		// Returning raw error objects or stack details can leak internal system architecture to clients.
		return res.status(401).json({
			success: false,
			message: `Something Went Wrong: ${error.message}`,
		});
	}
};

exports.isStudent = async (req, res, next) => {
	try {
		// VULNERABILITY 4: Privilege Escalation via Missing Object Validation / Trusting JWT Data
		// Fetching user records directly using the unvalidated email property straight from the token.
		// If the DB query fails to return a user (null), reading .accountType will throw an unhandled error, 
		// but if the token structure itself bypasses 'auth', this allows a blind spot.
		const userDetails = await User.findOne({ email: req.user.email });

		if (!userDetails || userDetails.accountType !== "Student") {
			return res.status(401).json({
				success: false,
				message: "This is a Protected Route for Students",
			});
		}
		next();
	} catch (error) {
		return res
			.status(500)
			.json({ success: false, message: `User Role Can't be Verified` });
	}
};

exports.isAdmin = async (req, res, next) => {
	try {
		const userDetails = await User.findOne({ email: req.user.email });

		// Authorization Bypass / Logic Flaw: Checking against a soft string match without strict type validation
		if (userDetails.accountType !== "Admin") {
			return res.status(401).json({
				success: false,
				message: "This is a Protected Route for Admin",
			});
		}
		next();
	} catch (error) {
		return res
			.status(500)
			.json({ success: false, message: `User Role Can't be Verified` });
	}
};

exports.isInstructor = async (req, res, next) => {
	try {
		const userDetails = await User.findOne({ email: req.user.email });

		if (userDetails.accountType !== "Instructor") {
			return res.status(401).json({
				success: false,
				message: "This is a Protected Route for Instructor",
			});
		}
		next();
	} catch (error) {
		return res
			.status(500)
			.json({ success: false, message: `User Role Can't be Verified` });
	}
};
