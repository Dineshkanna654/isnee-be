
import { Injectable, ConflictException, UnauthorizedException, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { AuthRepo } from './auth.repo';
import { EmailService } from '../email/email.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResetPasswordDto, RequestPasswordResetDto } from './dto/reset-password.dto';
import { PhoneVerificationDto, Enable2FADto, Verify2FADto, ResendOTPDto } from './dto/verify-2fa.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepo: AuthRepo,
    private readonly emailService: EmailService,
  ) {}

  private generateTokens(userId: string, email: string) {
    const accessToken = jwt.sign(
      { userId, email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    const refreshToken = jwt.sign(
      { userId, email, type: 'refresh' },
      process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
      { expiresIn: '30d' }
    );

    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    return { accessToken, refreshToken, expiresAt, refreshExpiresAt };
  }

  private generateId(): string {
    return crypto.randomUUID();
  }

  async signup(signupDto: SignupDto, ipAddress?: string, userAgent?: string) {
    const existingUser = await this.authRepo.findUserByEmail(signupDto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await bcrypt.hash(signupDto.password, 12);

    const user = await this.authRepo.createUser({
      id: this.generateId(),
      email: signupDto.email,
      full_name: signupDto.full_name,
      password_hash: hashedPassword,
      phone_number: signupDto.phone_number,
      phone_country_code: signupDto.phone_country_code || '+91',
      alternate_phone: signupDto.alternate_phone,
      is_active: true,
      is_email_verified: false,
      is_phone_verified: false,
      login_attempts: 0,
      metadata: {},
    });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    await this.authRepo.createEmailVerification({
      id: this.generateId(),
      users: { connect: { id: user.id } },
      token: verificationToken,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    try {
      await this.emailService.sendVerificationEmail(user.email, verificationToken);
    } catch (error) {
      console.error('Failed to send verification email:', error.message);
    }

    const tokens = this.generateTokens(user.id, user.email);

    await this.authRepo.createUserSession({
      id: this.generateId(),
      users: { connect: { id: user.id } },
      session_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      ip_address: ipAddress,
      user_agent: userAgent,
      expires_at: tokens.expiresAt,
      refresh_token_expires_at: tokens.refreshExpiresAt,
      is_active: true,
    });

    const { password_hash, ...userWithoutPassword } = user;

    return {
      user: userWithoutPassword,
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      verification_sent: true,
    };
  }

  async login(loginDto: LoginDto, ipAddress?: string, userAgent?: string) {
    const user = await this.authRepo.findUserByEmail(loginDto.email);

    if (!user || user.is_deleted) {
      throw new UnauthorizedException('Invalid email or password');
    }

    if (user.locked_until && user.locked_until > new Date()) {
      throw new ForbiddenException('Account is locked. Please try again later');
    }

    if (!user.is_active) {
      throw new ForbiddenException('Account is inactive');
    }

    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password_hash);

    if (!isPasswordValid) {
      const newAttempts = user.login_attempts + 1;
      const lockAccount = newAttempts >= 5;

      await this.authRepo.updateUser(user.id, {
        login_attempts: newAttempts,
        locked_until: lockAccount ? new Date(Date.now() + 30 * 60 * 1000) : null,
        updated_at: new Date(),
      });

      if (lockAccount) {
        throw new ForbiddenException('Account locked due to multiple failed attempts');
      }
      throw new UnauthorizedException('Invalid email or password');
    }

    await this.authRepo.deactivateUserSessions(user.id);

    const updatedUser = await this.authRepo.updateUser(user.id, {
      login_attempts: 0,
      last_login_at: new Date(),
      locked_until: null,
      updated_at: new Date(),
    });

    const tokens = this.generateTokens(user.id, user.email);

    await this.authRepo.createUserSession({
      id: this.generateId(),
      users: { connect: { id: user.id } },
      session_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      ip_address: ipAddress,
      user_agent: userAgent,
      expires_at: tokens.expiresAt,
      refresh_token_expires_at: tokens.refreshExpiresAt,
      is_active: true,
    });

    const { password_hash, ...userWithoutPassword } = updatedUser;

    return {
      user: userWithoutPassword,
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  async logout(userId: string, sessionToken: string) {
    await this.authRepo.deactivateUserSessionByToken(userId, sessionToken);
    return { message: 'Logged out successfully' };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto, ipAddress?: string, userAgent?: string) {
    const session = await this.authRepo.findSessionByRefreshToken(refreshTokenDto.refresh_token);

    if (!session) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const tokens = this.generateTokens(session.user_id, session.users.email);

    await this.authRepo.updateUserSession(session.id, {
      session_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      expires_at: tokens.expiresAt,
      refresh_token_expires_at: tokens.refreshExpiresAt,
      last_accessed_at: new Date(),
      ip_address: ipAddress || session.ip_address,
      user_agent: userAgent || session.user_agent,
    });

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  async verifyEmail(verifyEmailDto: VerifyEmailDto) {
    const verification = await this.authRepo.findEmailVerificationByToken(verifyEmailDto.token);

    if (!verification) {
      throw new NotFoundException('Invalid verification token');
    }

    if (verification.verified_at) {
      throw new BadRequestException('Email already verified');
    }

    if (verification.expires_at < new Date()) {
      throw new BadRequestException('Verification token expired');
    }

    await this.authRepo.updateEmailVerification(verification.id, {
      verified_at: new Date(),
    });

    await this.authRepo.updateUser(verification.user_id, {
      is_email_verified: true,
    });

    return { message: 'Email verified successfully' };
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDto) {
    const user = await this.authRepo.findUserByEmail(requestPasswordResetDto.email);

    if (!user || user.is_deleted) {
      return { message: 'If the email exists, a reset link has been sent' };
    }

    const resetToken = crypto.randomBytes(32).toString('hex');

    await this.authRepo.invalidatePasswordResetTokens(user.id);

    await this.authRepo.createPasswordResetToken({
      id: this.generateId(),
      users: { connect: { id: user.id } },
      token: resetToken,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
    });

    try {
      await this.emailService.sendPasswordResetEmail(user.email, resetToken);
    } catch (error) {
      console.error('Failed to send password reset email:', error.message);
    }

    return { message: 'If the email exists, a reset link has been sent' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const resetToken = await this.authRepo.findPasswordResetByToken(resetPasswordDto.token);

    if (!resetToken || resetToken.used_at) {
      throw new NotFoundException('Invalid or expired reset token');
    }

    if (resetToken.expires_at < new Date()) {
      throw new BadRequestException('Reset token expired');
    }

    const hashedPassword = await bcrypt.hash(resetPasswordDto.new_password, 12);

    await this.authRepo.updateUser(resetToken.user_id, {
      password_hash: hashedPassword,
      password_changed_at: new Date(),
      login_attempts: 0,
      locked_until: null,
    });

    await this.authRepo.updatePasswordResetToken(resetToken.id, {
      used_at: new Date(),
    });

    await this.authRepo.deactivateUserSessions(resetToken.user_id);

    return { message: 'Password reset successfully' };
  }

  async resendVerificationEmail(userId: string) {
    const user = await this.authRepo.findUserById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.is_email_verified) {
      throw new BadRequestException('Email already verified');
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');

    await this.authRepo.invalidateEmailVerifications(userId);

    await this.authRepo.createEmailVerification({
      id: this.generateId(),
      users: { connect: { id: userId } },
      token: verificationToken,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    try {
      await this.emailService.sendVerificationEmail(user.email, verificationToken);
    } catch (error) {
      console.error('Failed to send verification email:', error.message);
      throw new BadRequestException('Failed to send verification email');
    }

    return { message: 'Verification email sent' };
  }

  async getSessionInfo(userId: string) {
    const user = await this.authRepo.findUserById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      users: { connect: { id: user.id } },
      email: user.email,
      full_name: user.full_name,
      is_email_verified: user.is_email_verified,
      is_phone_verified: user.is_phone_verified,
    };
  }

  async verifyPhoneNumber(phoneVerificationDto: PhoneVerificationDto) {
    throw new BadRequestException('Phone verification not implemented yet');
  }

  async enable2FA(enable2FADto: Enable2FADto) {
    const user = await this.authRepo.findUserById(enable2FADto.userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const metadata = (user.metadata as any) || {};
    metadata.security = {
      ...metadata.security,
      twoFactorEnabled: true,
      twoFactorMethod: enable2FADto.method,
    };

    await this.authRepo.updateUser(enable2FADto.userId, {
      metadata: metadata,
    });

    const backupCodes = Array.from({ length: 10 }, () =>
      crypto.randomBytes(4).toString('hex').toUpperCase()
    );

    return {
      backup_codes: backupCodes,
      qr_code: null,
    };
  }

  async verify2FA(verify2FADto: Verify2FADto) {
    const user = await this.authRepo.findUserById(verify2FADto.userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const tokens = this.generateTokens(user.id, user.email);

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    };
  }

  async resendOTP(resendOTPDto: ResendOTPDto) {
    const user = await this.authRepo.findUserById(resendOTPDto.userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      sent: true,
      message: `OTP feature not implemented yet`,
    };
  }

  async getUserSecurity(userId: string) {
    const user = await this.authRepo.getSecurityInfo(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const metadata = (user.metadata as any) || {};

    return {
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        is_email_verified: user.is_email_verified,
        is_phone_verified: user.is_phone_verified,
        last_login_at: user.last_login_at,
      },
      security: {
        two_factor_enabled: metadata.security?.twoFactorEnabled || false,
        two_factor_method: metadata.security?.twoFactorMethod,
        trusted_devices: (metadata.security?.trustedDevices || []).map((device: any) => ({
          id: device.id,
          name: device.name,
          last_used: device.lastUsed,
        })),
        login_history: metadata.security?.loginHistory || [],
      },
      preferences: metadata.preferences || {},
    };
  }
}
