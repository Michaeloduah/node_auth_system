// src/api/controllers/auth.controller.js
const httpStatus = require('http-status');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const prisma = require('../../../config/prisma');
const ApiError = require('../../utils/ApiError');
const { generateAuthTokens } = require('../../services/token.service');
const { createUserSession } = require('../../services/session.service');

/**
 * Login with email and password
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<void>}
 */
const login = async (req, res, next) => {
  try {
    const { email, password, deviceInfo } = req.body;
    
    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email }
    });
    
    // Check if user exists
    if (!user) {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid email or password');
    }
    
    // Check if user is active
    if (!user.isActive) {
      throw new ApiError(httpStatus.FORBIDDEN, 'Account is disabled, please contact support');
    }
    
    // Validate password
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid email or password');
    }
    
    // Generate authentication tokens
    const tokens = await generateAuthTokens(user);
    
    // Create user session
    const ipAddress = req.ip || req.connection.remoteAddress;
    await createUserSession({
      userId: user.id,
      deviceInfo: deviceInfo || req.headers['user-agent'],
      ipAddress,
      refreshToken: tokens.refreshToken
    });
    
    // Remove sensitive data
    const userResponse = {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      role: user.role
    };
    
    // Set refresh token in HTTP-only cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: 'strict'
    });
    
    // Send response
    res.status(httpStatus.OK).send({
      user: userResponse,
      tokens: {
        accessToken: tokens.accessToken,
        expiresIn: process.env.JWT_ACCESS_EXPIRATION_MINUTES * 60
      }
    });
    
  } catch (error) {
    next(error);
  }
};

module.exports = {
  login
};