
import { Module } from '@nestjs/common';
import { TeamMembersService } from './team-members.service';
import { TeamMembersController } from './team-members.controller';
import { TeamMembersRepo } from './team-members.repo';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [TeamMembersController],
  providers: [TeamMembersService, TeamMembersRepo],
  exports: [TeamMembersService],
})
export class TeamMembersModule {}
