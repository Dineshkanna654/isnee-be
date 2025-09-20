
import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  Request,
} from '@nestjs/common';
import { TeamMembersService } from './team-members.service';
import { CreateTeamMemberDto } from './dto/create-team-member.dto';
import { UpdateTeamMemberDto } from './dto/update-team-member.dto';

@Controller('team-members')
export class TeamMembersController {
  constructor(private readonly teamMembersService: TeamMembersService) {}

  @Get('stats')
  async getStats() {
    return await this.teamMembersService.getStats();
  }

  @Post()
  async create(@Body() createTeamMemberDto: CreateTeamMemberDto) {
    return await this.teamMembersService.create(createTeamMemberDto);
  }

  @Get()
  async findAll(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('search') search?: string,
    @Query('isApproved') isApproved?: string,
  ) {
    return await this.teamMembersService.findAll({
      page: page ? parseInt(page, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
      search,
      isApproved: isApproved === 'true' ? true : isApproved === 'false' ? false : undefined,
    });
  }

  @Get('my-memberships')
  async getMyMemberships(@Request() req: any) {
    // TODO: Get userId from authenticated request
    const userId = req.user?.id || 'test-user-id';
    return await this.teamMembersService.findByUserId(userId);
  }

  @Get('pending-approvals')
  async getPendingApprovals() {
    return await this.teamMembersService.findPendingApprovals();
  }

  @Get('by-designation/:designation')
  async getByDesignation(@Param('designation') designation: string) {
    return await this.teamMembersService.findByDesignation(designation);
  }

  @Get('team/:teamId')
  async getByTeamId(@Param('teamId') teamId: string) {
    return await this.teamMembersService.findByTeamId(teamId);
  }

  @Get('user/:userId')
  async getByUserId(@Param('userId') userId: string) {
    return await this.teamMembersService.findByUserId(userId);
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    return await this.teamMembersService.findOne(id);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() updateTeamMemberDto: UpdateTeamMemberDto,
  ) {
    return await this.teamMembersService.update(id, updateTeamMemberDto);
  }

  @Delete(':id')
  async remove(@Param('id') id: string) {
    return await this.teamMembersService.remove(id);
  }

  @Patch(':id/approve')
  async approve(@Param('id') id: string) {
    return await this.teamMembersService.approve(id);
  }

  @Patch(':id/reject')
  async reject(@Param('id') id: string) {
    return await this.teamMembersService.reject(id);
  }

  @Post('bulk/approve')
  async bulkApprove(@Body('ids') ids: string[]) {
    return await this.teamMembersService.bulkApprove(ids);
  }

  @Post('bulk/remove')
  async bulkRemove(@Body('ids') ids: string[]) {
    return await this.teamMembersService.bulkRemove(ids);
  }
}
