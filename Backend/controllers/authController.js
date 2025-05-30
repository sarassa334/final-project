import UserModel from "../models/userModel.js";
import {
  registerSchema,
  loginSchema,
  changePasswordSchema,
} from "../utils/validation.js";

const AuthController = {
  //=================================
  async register(req, res, next) {
    try {
      //validation
      const { error, value } = registerSchema.validate(req.body); // Uses registerSchema from validation.js to validate incoming data (req.body).
      if (error) throw new Error(error.details[0].message);
      //Destructuring Validated Values
      const { email, password, name } = value; // It makes the code cleaner and shorter — instead of repeating value.email, value.password, etc., we just unpack them at once.
      //Check for Existing User
      const existingUser = await UserModel.findByEmail(email);
      if (existingUser) throw new Error("Email already in use");
      //Create User
      const user = await UserModel.create({ email, password, name });
      // Generate Token
      const token = UserModel.generateToken(user.id);// actual JWT token
      //Create Session
      req.session.userId = user.id; // You're storing the user's ID (from the database) inside the session.
      req.session.authenticated = true; // This is a custom flag
      //Set Cookie
      res.cookie("token", token, { // You are naming the cookie "token" // token – the value you’re saving in the cookie
        httpOnly: true,//This means: JavaScript on the browser cannot read this cookie (for security)
        secure: process.env.NODE_ENV === "production",// explaination below
        maxAge: 24 * 60 * 60 * 1000, // fter 24 hours, the browser will delete this cookie automatically
        sameSite: "strict", //"strict" is the most secure option, but sometimes websites choose "lax" or "none" depending on their needs
      });
      //===============
      //Respond to Client : Returns token and user data (without password) to frontend
      res.status(201).json({// JSON is the format used by frontend apps to receive and handle data
        success: true,//A flag that tells the frontend: everything went well
        token,//The frontend will save this token and use it in headers for future API requests
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          createdAt: user.created_at,
        },
      });
    } catch (error) {
      next(error); // sends error to Express’s error handler middleware
    }
  },
  //=================================
  async login(req, res, next) {
    try {
      const { error, value } = loginSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { email, password } = value;

      const user = await UserModel.findByEmail(email);
      if (!user) throw new Error("Invalid credentials");

      const isMatch = await UserModel.verifyPassword(password, user.password);
      if (!isMatch) throw new Error("Invalid credentials");

      //creat the session

      req.session.userId = user.id;
      req.session.authenticated = true;

      const token = UserModel.generateToken(user.id);
      //set this token insied the cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: "strict",
      });

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      });
    } catch (error) {
      next(error);
    }
  },
  //=================================
  async getMe(req, res, next) {
    try {
      const user = await UserModel.findById(req.user.id);
      if (!user) throw new Error("User not found");

      res.json({
        success: true,
        user,
      });
    } catch (error) {
      next(error);
    }
  },
  //=================================
  async changePassword(req, res, next) {
    try {
      const { error, value } = changePasswordSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { currentPassword, newPassword } = value;
      const user = await UserModel.findByEmail(req.user.email);

      const isMatch = await UserModel.verifyPassword(
        currentPassword, //  the user sent
        user.password
      );
      if (!isMatch) throw new Error("Current password is incorrect");

      await UserModel.updatePassword(req.user.id, newPassword);

      res.json({
        success: true,
        message: "Password updated successfully",
      });
    } catch (error) {
      next(error);
    }
  },
  //=================================
  //mehtode for logout
  //destroy the session and clear value in cookies
  async logout(req, res, next) {
    try {
      req.session.destroy((err) => {//This removes the session data from the server.
        if (err) throw err;
      });
      res.clearCookie("token");
      res.clearCookie("connect.sid");//This removes the session identifier stored in the browser // connect.sid is the default cookie name used by express-session.
      res.json({ success: true, message: "logged out " });
    } catch (error) {}
  },
};

export default AuthController;


// Notes:
//==================
//get the data
//make validate the data that i get form body in utils validation.js
//if the passwaord does not mathch the user passowrd

//================================

// req.session is how you remember the user on the server.
// userId = who the user is
// authenticated = whether the user is logged in
// This data stays stored until the user logs out or the session expires

//================================

// secure: process.env.NODE_ENV === "production"
// This means: only use HTTPS (secure connection) in production
// During development (NODE_ENV=development), this will be false so you can test locally
// In production, this will be true, and the cookie will only be sent over HTTPS

//================================

// 📦 Link with Other Files:
// File	Role
// UserModel	Created the user in the DB, returned their info
// AuthController	Received the user from the model, created the token, created the session, and now responds
// Frontend	Will receive this response, store the token (e.g., in memory or localStorage), and show user data