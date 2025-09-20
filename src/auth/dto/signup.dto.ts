import { IsEmail, IsString, IsOptional, IsBoolean, MinLength, MaxLength, Matches } from 'class-validator';

export class SignupDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(2)
  @MaxLength(255)
  full_name: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
  })
  password: string;

  @IsString()
  @Matches(/^[0-9]{10}$/, { message: 'Phone number must be exactly 10 digits' })
  phone_number: string;

  @IsOptional()
  @IsString()
  @Matches(/^\+[0-9]{1,4}$/, { message: 'Phone country code must start with + followed by 1-4 digits' })
  phone_country_code?: string;

  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{10}$/, { message: 'Alternate phone must be exactly 10 digits' })
  alternate_phone?: string;

  @IsOptional()
  @IsBoolean()
  acceptTerms?: boolean;

  @IsOptional()
  @IsBoolean()
  marketingConsent?: boolean;
}