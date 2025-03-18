// src/services/session.service.js
const moment = require('dayjs');
const prisma = require('../config/prisma');

/**
 * Create user session
 * @param {Object} sessionData
 * @param {string} sessionData.userId
 * @param {string} sessionData.deviceInfo
 * @param {string} sessionData.ipAddress
 * @param {string} sessionData.refreshToken
 * @returns {Promise<Object>}
 */
const createUserSession = async ({ userId, deviceInfo, ipAddress, refreshToken }) => {
  // Sessions expire after 30 days of inactivity by default
  const expirationDays = parseInt(process.env.SESSION_EXPIRATION_DAYS || '30', 10);
  
  const session = await prisma.session.create({
    data: {
      userId,
      deviceInfo,
      ipAddress,
      lastActiveAt: new Date(),
      expiresAt: moment().add(expirationDays, 'days').toDate(),
      isRevoked: false
    }
  });
  
  return session;
};

/**
 * Update session activity
 * @param {string} sessionId
 * @returns {Promise<Object>}
 */
const updateSessionActivity = async (sessionId) => {
  const expirationDays = parseInt(process.env.SESSION_EXPIRATION_DAYS || '30', 10);
  
  const session = await prisma.session.update({
    where: { id: sessionId },
    data: {
      lastActiveAt: new Date(),
      expiresAt: moment().add(expirationDays, 'days').toDate(),
    }
  });
  
  return session;
};

/**
 * Revoke user session
 * @param {string} sessionId
 * @returns {Promise<Object>}
 */
const revokeSession = async (sessionId) => {
  const session = await prisma.session.update({
    where: { id: sessionId },
    data: {
      isRevoked: true
    }
  });
  
  return session;
};

/**
 * Get user active sessions
 * @param {string} userId
 * @returns {Promise<Array>}
 */
const getUserActiveSessions = async (userId) => {
  const sessions = await prisma.session.findMany({
    where: {
      userId,
      isRevoked: false,
      expiresAt: {
        gt: new Date()
      }
    },
    orderBy: {
      lastActiveAt: 'desc'
    }
  });
  
  return sessions;
};

module.exports = {
  createUserSession,
  updateSessionActivity,
  revokeSession,
  getUserActiveSessions
};