
import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';
import { TeamMembersRepo } from './team-members.repo';
import { CreateTeamMemberDto } from './dto/create-team-member.dto';
import { UpdateTeamMemberDto } from './dto/update-team-member.dto';

@Injectable()
export class TeamMembersService {
  constructor(private readonly teamMembersRepo: TeamMembersRepo) {}

  async create(createTeamMemberDto: CreateTeamMemberDto) {
    try {
      return await this.teamMembersRepo.create({
        id: crypto.randomUUID(),
        users_team_members_user_idTousers: { connect: { id: createTeamMemberDto.userId } },
        teams: { connect: { id: createTeamMemberDto.teamId } },
        designation: createTeamMemberDto.designation as any,
        is_approved: createTeamMemberDto.isApproved || false,
      });
    } catch (error) {
      throw new BadRequestException('Failed to create team member');
    }
  }

  async findAll(params?: {
    page?: number;
    limit?: number;
    search?: string;
    isApproved?: boolean;
  }) {
    const page = params?.page || 1;
    const limit = params?.limit || 10;
    const skip = (page - 1) * limit;

    const where: any = {};
    if (params?.isApproved !== undefined) {
      where.is_approved = params.isApproved;
    }
    if (params?.search) {
      where.OR = [
        { designation: { contains: params.search, mode: 'insensitive' } },
        { users_team_members_user_idTousers: { full_name: { contains: params.search, mode: 'insensitive' } } },
        { users_team_members_user_idTousers: { email: { contains: params.search, mode: 'insensitive' } } },
      ];
    }

    const [data, total] = await Promise.all([
      this.teamMembersRepo.findAll({
        skip,
        take: limit,
        where,
        orderBy: { created_at: 'desc' },
      }),
      this.teamMembersRepo.count(where),
    ]);

    return {
      success: true,
      data,
      pagination: {
        total,
        page,
        pages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(id: string) {
    const teamMember = await this.teamMembersRepo.findOne(id);
    if (!teamMember) {
      throw new NotFoundException('Team member not found');
    }
    return teamMember;
  }

  async findByUserId(userId: string) {
    return await this.teamMembersRepo.findByUserId(userId);
  }

  async findByTeamId(teamId: string) {
    return await this.teamMembersRepo.findByTeamId(teamId);
  }

  async findByDesignation(designation: string) {
    return await this.teamMembersRepo.findByDesignation(designation);
  }

  async findPendingApprovals() {
    return await this.teamMembersRepo.findPendingApprovals();
  }

  async update(id: string, updateTeamMemberDto: UpdateTeamMemberDto) {
    const exists = await this.teamMembersRepo.findOne(id);
    if (!exists) {
      throw new NotFoundException('Team member not found');
    }

    const updateData: any = {};
    if (updateTeamMemberDto.designation) {
      updateData.designation = updateTeamMemberDto.designation;
    }
    if (updateTeamMemberDto.isApproved !== undefined) {
      updateData.is_approved = updateTeamMemberDto.isApproved;
      if (updateTeamMemberDto.isApproved) {
        updateData.approved_at = new Date();
      }
    }

    return await this.teamMembersRepo.update(id, updateData);
  }

  async approve(id: string) {
    const exists = await this.teamMembersRepo.findOne(id);
    if (!exists) {
      throw new NotFoundException('Team member not found');
    }
    if (exists.is_approved) {
      throw new BadRequestException('Team member is already approved');
    }
    return await this.teamMembersRepo.approve(id);
  }

  async reject(id: string) {
    const exists = await this.teamMembersRepo.findOne(id);
    if (!exists) {
      throw new NotFoundException('Team member not found');
    }
    return await this.teamMembersRepo.reject(id);
  }

  async bulkApprove(ids: string[]) {
    if (!ids || ids.length === 0) {
      throw new BadRequestException('No team member IDs provided');
    }
    const result = await this.teamMembersRepo.bulkApprove(ids);
    return {
      success: true,
      message: `${result.count} team members approved`,
    };
  }

  async bulkRemove(ids: string[]) {
    if (!ids || ids.length === 0) {
      throw new BadRequestException('No team member IDs provided');
    }
    const result = await this.teamMembersRepo.bulkRemove(ids);
    return {
      success: true,
      message: `${result.count} team members removed`,
    };
  }

  async remove(id: string) {
    const exists = await this.teamMembersRepo.findOne(id);
    if (!exists) {
      throw new NotFoundException('Team member not found');
    }
    await this.teamMembersRepo.remove(id);
    return { success: true, message: 'Team member removed successfully' };
  }

  async getStats() {
    return await this.teamMembersRepo.getStats();
  }
}
