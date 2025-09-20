import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthRepo {
  constructor(private prisma: PrismaService) {}

  async createUser(data: Prisma.usersCreateInput) {
    return this.prisma.users.create({
      data,
    });
  }

  async findUserByEmail(email: string) {
    return this.prisma.users.findUnique({
      where: { email },
    });
  }

  async findUserById(id: string) {
    return this.prisma.users.findUnique({
      where: { id },
    });
  }

  async updateUser(id: string, data: Prisma.usersUpdateInput) {
    return this.prisma.users.update({
      where: { id },
      data,
    });
  }

  async createEmailVerification(data: Prisma.email_verificationsCreateInput) {
    return this.prisma.email_verifications.create({
      data,
    });
  }

  async findEmailVerificationByToken(token: string) {
    return this.prisma.email_verifications.findUnique({
      where: { token },
      include: { users: true },
    });
  }

  async updateEmailVerification(id: string, data: Prisma.email_verificationsUpdateInput) {
    return this.prisma.email_verifications.update({
      where: { id },
      data,
    });
  }

  async invalidateEmailVerifications(userId: string) {
    return this.prisma.email_verifications.updateMany({
      where: {
        user_id: userId,
        verified_at: null,
      },
      data: {
        expires_at: new Date(),
      },
    });
  }

  async createPasswordResetToken(data: Prisma.password_reset_tokensCreateInput) {
    return this.prisma.password_reset_tokens.create({
      data,
    });
  }

  async findPasswordResetByToken(token: string) {
    return this.prisma.password_reset_tokens.findUnique({
      where: { token },
      include: { users: true },
    });
  }

  async updatePasswordResetToken(id: string, data: Prisma.password_reset_tokensUpdateInput) {
    return this.prisma.password_reset_tokens.update({
      where: { id },
      data,
    });
  }

  async invalidatePasswordResetTokens(userId: string) {
    return this.prisma.password_reset_tokens.updateMany({
      where: { user_id: userId, used_at: null },
      data: { used_at: new Date() },
    });
  }

  async createUserSession(data: Prisma.user_sessionsCreateInput) {
    return this.prisma.user_sessions.create({
      data,
    });
  }

  async findSessionByRefreshToken(refreshToken: string) {
    return this.prisma.user_sessions.findFirst({
      where: {
        refresh_token: refreshToken,
        is_active: true,
        refresh_token_expires_at: {
          gt: new Date(),
        },
      },
      include: {
        users: true,
      },
    });
  }

  async updateUserSession(id: string, data: Prisma.user_sessionsUpdateInput) {
    return this.prisma.user_sessions.update({
      where: { id },
      data,
    });
  }

  async deactivateUserSessions(userId: string) {
    return this.prisma.user_sessions.updateMany({
      where: { user_id: userId, is_active: true },
      data: { is_active: false },
    });
  }

  async deactivateUserSessionByToken(userId: string, sessionToken: string) {
    return this.prisma.user_sessions.updateMany({
      where: { user_id: userId, session_token: sessionToken },
      data: { is_active: false },
    });
  }


  async getSecurityInfo(userId: string) {
    return this.prisma.users.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        full_name: true,
        is_email_verified: true,
        is_phone_verified: true,
        phone_number: true,
        metadata: true,
        last_login_at: true,
        created_at: true,
      },
    });
  }
}