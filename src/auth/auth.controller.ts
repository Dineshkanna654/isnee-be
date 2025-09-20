
import {
  Controller,
  Post,
  Body,
  Get,
  Request,
  UseGuards,
  Patch,
  Param,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResetPasswordDto, RequestPasswordResetDto } from './dto/reset-password.dto';
import { PhoneVerificationDto, Enable2FADto, Verify2FADto, ResendOTPDto } from './dto/verify-2fa.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private getClientIP(req: any): string | undefined {
    return req.ip || req.connection?.remoteAddress || undefined;
  }

  private getUserAgent(req: any): string | undefined {
    const userAgent = req.headers['user-agent'];
    return typeof userAgent === 'string' ? userAgent : undefined;
  }

  @Post('signup')
  async signup(@Body() signupDto: SignupDto, @Request() req: any) {
    const ipAddress = this.getClientIP(req);
    const userAgent = this.getUserAgent(req);

    const result = await this.authService.signup(signupDto, ipAddress, userAgent);

    return {
      success: true,
      data: {
        user: result.user,
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        verification_sent: result.verification_sent,
      },
      message: 'User registered successfully. Please check your email to verify your account.',
    };
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto, @Request() req: any) {
    const ipAddress = this.getClientIP(req);
    const userAgent = this.getUserAgent(req);

    const result = await this.authService.login(loginDto, ipAddress, userAgent);

    return {
      success: true,
      data: {
        user: result.user,
        access_token: result.access_token,
        refresh_token: result.refresh_token,
      },
    };
  }

  @Post('logout')
  async logout(@Request() req: any) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const userId = req.user?.id;

    if (!userId || !token) {
      return {
        success: false,
        message: 'Invalid request',
      };
    }

    const result = await this.authService.logout(userId, token);

    return {
      success: true,
      message: result.message,
    };
  }

  @Post('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto, @Request() req: any) {
    const ipAddress = this.getClientIP(req);
    const userAgent = this.getUserAgent(req);

    const result = await this.authService.refreshToken(refreshTokenDto, ipAddress, userAgent);

    return {
      success: true,
      data: {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
      },
    };
  }

  @Post('verify-email')
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    const result = await this.authService.verifyEmail(verifyEmailDto);

    return {
      success: true,
      message: result.message,
    };
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() requestPasswordResetDto: RequestPasswordResetDto) {
    const result = await this.authService.requestPasswordReset(requestPasswordResetDto);

    return {
      success: true,
      message: result.message,
    };
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const result = await this.authService.resetPassword(resetPasswordDto);

    return {
      success: true,
      message: result.message,
    };
  }

  @Post('resend-verification')
  async resendVerificationEmail(@Request() req: any) {
    const userId = req.user?.id;

    if (!userId) {
      return {
        success: false,
        message: 'Invalid request',
      };
    }

    const result = await this.authService.resendVerificationEmail(userId);

    return {
      success: true,
      message: result.message,
    };
  }

  @Get('session')
  async getSessionInfo(@Request() req: any) {
    const userId = req.user?.id;

    if (!userId) {
      return {
        success: false,
        message: 'Not authenticated',
      };
    }

    const result = await this.authService.getSessionInfo(userId);

    return {
      success: true,
      data: result,
    };
  }

  @Post('verify-phone')
  async verifyPhoneNumber(@Body() phoneVerificationDto: PhoneVerificationDto) {
    try {
      await this.authService.verifyPhoneNumber(phoneVerificationDto);
      return {
        success: true,
        message: 'Phone number verified successfully',
      };
    } catch (error) {
      return {
        success: false,
        message: error.message,
      };
    }
  }

  @Post('enable-2fa')
  async enable2FA(@Body() enable2FADto: Enable2FADto) {
    const result = await this.authService.enable2FA(enable2FADto);

    return {
      success: true,
      data: {
        backup_codes: result.backup_codes,
        qr_code: result.qr_code,
      },
      message: '2FA enabled successfully. Please save your backup codes in a secure place.',
    };
  }

  @Post('verify-2fa')
  async verify2FA(@Body() verify2FADto: Verify2FADto) {
    const result = await this.authService.verify2FA(verify2FADto);

    return {
      success: true,
      data: {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
      },
      message: '2FA verification successful.',
    };
  }

  @Post('resend-otp')
  async resendOTP(@Body() resendOTPDto: ResendOTPDto) {
    const result = await this.authService.resendOTP(resendOTPDto);

    return {
      success: true,
      data: { sent: result.sent },
      message: result.message,
    };
  }

  @Get('security')
  async getUserSecurity(@Request() req: any) {
    const userId = req.user?.id;

    if (!userId) {
      return {
        success: false,
        message: 'Not authenticated',
      };
    }

    const result = await this.authService.getUserSecurity(userId);

    return {
      success: true,
      data: result,
    };
  }
}
