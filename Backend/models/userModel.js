import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { query } from "../config/db.js";

const UserModel = {
  // Handle user registration
  async create({ email, password, name }) {
    try {
      const hashedPassword = await bcrypt.hash(
        password,
        parseInt(process.env.BCRYPT_SALT_ROUNDS) // parseInt ===> because environment variable is a string by default and i want this as number
      );

      const { rows } = await query(
        `INSERT INTO users (email, password, name) 
         VALUES ($1, $2, $3) 
         RETURNING id, email, name, created_at`, // After inserting the new row, give me back specific column values from that row
        [email, hashedPassword, name] //This array is the list of values that will be safely inserted
      );

      return rows[0];
    } catch (error) {
      if (error.code === "23505") {
        throw new Error("Email already exists");
      }
      throw error;
    }
  },
  // Handle user login
  async findByEmail(email) {
    const { rows } = await query(
      "SELECT id, email, password, name FROM users WHERE email = $1",
      [email]
    );
    return rows[0]; // if this line not exists :  Will return: undefined Because in JavaScript, if a function doesn’t have a return, it returns undefined by default.
  },
  // Handle fetching user info
  async findById(id) {
    const { rows } = await query(
      "SELECT id, email, name FROM users WHERE id = $1",
      [id]
    );
    return rows[0];
  },
  //Handle authentication tokens
  generateToken(userId) { // sync ===> You get the token right away, and then move forward.
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    });
  },
  // Handle user login
  async verifyPassword(candidatePassword, hashedPassword) {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  }, // return true / false 

  // Handle updating passwords
  async updatePassword(userId, newPassword) {
    const hashedPassword = await bcrypt.hash( // Hashes the new password
      newPassword,
      parseInt(process.env.BCRYPT_SALT_ROUNDS)
    );
    await query("UPDATE users SET password = $1 WHERE id = $2", [ // Stores it in the DB using UPDATE
      hashedPassword,
      userId,
    ]);
  },
};

export default UserModel;



// Method	What it does
// create()	Adds new user to the database (used for registration)
// findByEmail()	Finds a user by their email (used in login)
// findById()	Finds a user by their ID (used to fetch profile)
// verifyPassword()	Compares password with the hashed one (used in login)
// generateToken()	Creates a JWT token to identify the user
// updatePassword()	Updates a user's password (used in settings / reset)

//===========================

// 🤓 Behind the scenes
// jwt.sign():
// Takes a JS object like { id: 7 }
// Adds some metadata (like expiration)
// Encodes it in base64
// Applies a crypto signature (HMAC-SHA256 or similar)
// ⚡ All of that is done in memory, with no waiting. That’s why it's sync.

//============================

// ✅ Final Understanding (Corrected & Confirmed):
// Async + await behaves like sync — the code waits for the result before continuing.
// ✅ We use this when:
// The function takes time (e.g., database, hashing).
// We need the result before continuing.
// Sync functions are already fast and blocking — no await needed.
// ✅ We use them when:
// The function runs quickly and gives the result immediately (e.g., jwt.sign()).
// Async without await means:
// The function starts in the background.
// The code doesn't wait — it moves on, even if the result isn’t ready.
// ❌ Use this only if:
// You don’t need the result immediately.
// You know it's safe to continue without it.

//==============================

// bcrypt.compare() ===>	Built-in function in bcrypt library
// verifyPassword	 ===> Your own method that calls bcrypt
// Inside call ===>	Just calls, not nested definitions
// so You’re wrapping bcrypt.compare in your own method verifyPassword so you can reuse it wherever you need it in your app.

