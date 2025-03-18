// src/services/token.service.js
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const moment = require('dayjs');
const prisma = require('../config/prisma');
const ApiError = require('../utils/ApiError');
const httpStatus = require('http-status');

/**
 * Generate token
 * @param {Object} payload
 * @param {string} secret
 * @param {number} expiration - Expiration time in minutes
 * @returns {string}
 */
const generateToken = (payload, secret, expiration) => {
  return jwt.sign(payload, secret, {
    expiresIn: `${expiration}m`
  });
};

/**
 * Generate auth tokens
 * @param {User} user
 * @returns {Object} - Access and refresh tokens
 */
const generateAuthTokens = async (user) => {
  const accessTokenExpires = parseInt(process.env.JWT_ACCESS_EXPIRATION_MINUTES, 10);
  const refreshTokenExpires = parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS, 10);
  
  const accessTokenPayload = {
    userId: user.id,
    role: user.role,
    type: 'access'
  };
  
  const refreshTokenPayload = {
    userId: user.id,
    type: 'refresh',
    tokenFamily: uuidv4() // Token family ID to prevent reuse of compromised tokens
  };
  
  const accessToken = generateToken(
    accessTokenPayload, 
    process.env.JWT_ACCESS_SECRET, 
    accessTokenExpires
  );
  
  const refreshToken = generateToken(
    refreshTokenPayload, 
    process.env.JWT_REFRESH_SECRET, 
    refreshTokenExpires * 24 * 60 // Convert days to minutes
  );
  
  // Save refresh token
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: moment().add(refreshTokenExpires, 'days').toDate(),
      isRevoked: false
    }
  });
  
  return {
    accessToken,
    refreshToken
  };
};

/**
 * Verify token and return token doc (or throw an error if it is not valid)
 * @param {string} token
 * @param {string} type - access or refresh
 * @returns {Promise<Object>}
 */
const verifyToken = async (token, type) => {
  try {
    const secret = type === 'access' 
      ? process.env.JWT_ACCESS_SECRET 
      : process.env.JWT_REFRESH_SECRET;
    
    const payload = jwt.verify(token, secret);
    
    if (type === 'refresh') {
      const refreshToken = await prisma.refreshToken.findFirst({
        where: {
          token,
          isRevoked: false,
          expiresAt: {
            gt: new Date()
          }
        }
      });
      
      if (!refreshToken) {
        throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid refresh token');
      }
    }
    
    return payload;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid token');
  }
};

module.exports = {
  generateToken,
  generateAuthTokens,
  verifyToken
};