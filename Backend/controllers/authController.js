import UserModel from '../models/userModel.js';
import { registerSchema, loginSchema, changePasswordSchema } from '../utils/validation.js';

const AuthController = {
  async register(req, res, next) {
    try {
      const { error, value } = registerSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { email, password, name } = value;
      
      const existingUser = await UserModel.findByEmail(email);
      if (existingUser) throw new Error('Email already in use');

      const user = await UserModel.create({ email, password, name });
      const token = UserModel.generateToken(user.id);
      
      res.status(201).json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          createdAt: user.created_at
        }
      });
    } catch (error) {
      next(error);
    }
  },

  async login(req, res, next) {
    try {
      const { error, value } = loginSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { email, password } = value;
      
      const user = await UserModel.findByEmail(email);
      if (!user) throw new Error('Invalid credentials');

      const isMatch = await UserModel.verifyPassword(password, user.password);
      if (!isMatch) throw new Error('Invalid credentials');

      const token = UserModel.generateToken(user.id);
      
      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      });
    } catch (error) {
      next(error);
    }
  },

  async getMe(req, res, next) {
    try {
      const user = await UserModel.findById(req.user.id);
      if (!user) throw new Error('User not found');

      res.json({
        success: true,
        user
      });
    } catch (error) {
      next(error);
    }
  },

  async changePassword(req, res, next) {
    try {
      const { error, value } = changePasswordSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { currentPassword, newPassword } = value;
      const user = await UserModel.findByEmail(req.user.email);

      const isMatch = await UserModel.verifyPassword(currentPassword, user.password);
      if (!isMatch) throw new Error('Current password is incorrect');

      await UserModel.updatePassword(req.user.id, newPassword);

      res.json({
        success: true,
        message: 'Password updated successfully'
      });
    } catch (error) {
      next(error);
    }
  }
};

export default AuthController;