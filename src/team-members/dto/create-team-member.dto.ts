import { IsString, IsBoolean, IsOptional, IsUUID, IsNotEmpty } from 'class-validator';

export class CreateTeamMemberDto {
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsUUID()
  @IsNotEmpty()
  teamId: string;

  @IsString()
  @IsNotEmpty()
  designation: string;

  @IsBoolean()
  @IsOptional()
  isApproved?: boolean;
}