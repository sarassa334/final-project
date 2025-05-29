import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { query } from '../config/db.js';

const UserModel = {
  async create({ email, password, name }) {
    try {
      const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS));
      
      const { rows } = await query(
        `INSERT INTO users (email, password, name) 
         VALUES ($1, $2, $3) 
         RETURNING id, email, name, created_at`,
        [email, hashedPassword, name]
      );
      
      return rows[0];
    } catch (error) {
      if (error.code === '23505') {
        throw new Error('Email already exists');
      }
      throw error;
    }
  },

  async findByEmail(email) {
    const { rows } = await query(
      'SELECT id, email, password, name FROM users WHERE email = $1',
      [email]
    );
    return rows[0];
  },

  async findById(id) {
    const { rows } = await query(
      'SELECT id, email, name FROM users WHERE id = $1',
      [id]
    );
    return rows[0];
  },

  generateToken(userId) {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    });
  },

  async verifyPassword(candidatePassword, hashedPassword) {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  },

  async updatePassword(userId, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_SALT_ROUNDS));
    await query(
      'UPDATE users SET password = $1 WHERE id = $2',
      [hashedPassword, userId]
    );
  }
};

export default UserModel;