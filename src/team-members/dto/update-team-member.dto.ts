import { PartialType } from '@nestjs/mapped-types';
import { CreateTeamMemberDto } from './create-team-member.dto';
import { IsBoolean, IsOptional } from 'class-validator';

export class UpdateTeamMemberDto extends PartialType(CreateTeamMemberDto) {
  @IsBoolean()
  @IsOptional()
  isApproved?: boolean;
}