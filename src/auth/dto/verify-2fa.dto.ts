import { IsString, IsUUID, IsIn, Length, Matches } from 'class-validator';

export class PhoneVerificationDto {
  @IsUUID()
  userId: string;

  @IsString()
  @Length(6, 6)
  @Matches(/^[0-9]{6}$/, { message: 'OTP must contain only digits' })
  otp: string;

  @IsString()
  @IsIn(['primary', 'alternate'])
  phoneType?: string;
}

export class Enable2FADto {
  @IsUUID()
  userId: string;

  @IsString()
  @IsIn(['sms', 'email', 'app'])
  method: string;
}

export class Verify2FADto {
  @IsUUID()
  userId: string;

  @IsString()
  @Length(6, 6)
  @Matches(/^[0-9]{6}$/, { message: 'Verification code must contain only digits' })
  code: string;
}

export class ResendOTPDto {
  @IsUUID()
  userId: string;

  @IsString()
  @IsIn(['phone', 'email'])
  type: string;
}