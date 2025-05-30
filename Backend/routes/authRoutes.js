import { Router } from 'express'; // This imports the Express Router class which lets you define routes in a separate file
import AuthController from '../controllers/authController.js';// You are importing all the logic from your authController.js file
import { authenticate } from '../middleware/auth.js';//This middleware checks if the user is authenticated before letting them access protected routes // For example, /me and /change-password must have a valid token/session.

const router = Router(); // Creates a new Router instance to define separate route handlers.

router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.get('/me', authenticate, AuthController.getMe);
router.put('/change-password', authenticate, AuthController.changePassword);

export default router;


// 🔁 Summary:
// /register	POST	You're creating a new user
// /login	POST	You're processing login credentials
// /me	GET 	You're just fetching your user info

//====================

// If you were to send /register or /login using GET, it wouldn't make sense:
// GET should not include a body.
// It's also less secure for sending passwords — because data can show in URLs.

