import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma } from '@prisma/client';

@Injectable()
export class TeamMembersRepo {
  constructor(private prisma: PrismaService) {}

  async create(data: Prisma.team_membersCreateInput) {
    return this.prisma.team_members.create({
      data,
      include: {
        users_team_members_user_idTousers: true,
        teams: true,
      },
    });
  }

  async findAll(params: {
    skip?: number;
    take?: number;
    cursor?: Prisma.team_membersWhereUniqueInput;
    where?: Prisma.team_membersWhereInput;
    orderBy?: Prisma.team_membersOrderByWithRelationInput;
  }) {
    const { skip, take, cursor, where, orderBy } = params;
    return this.prisma.team_members.findMany({
      skip,
      take,
      cursor,
      where,
      orderBy,
      include: {
        users_team_members_user_idTousers: true,
        teams: {
          include: {
            institutes: true,
          },
        },
      },
    });
  }

  async findOne(id: string) {
    return this.prisma.team_members.findUnique({
      where: { id },
      include: {
        users_team_members_user_idTousers: true,
        teams: {
          include: {
            institutes: true,
          },
        },
      },
    });
  }

  async findByUserId(userId: string) {
    return this.prisma.team_members.findMany({
      where: { user_id: userId },
      include: {
        teams: {
          include: {
            institutes: true,
          },
        },
      },
    });
  }

  async findByTeamId(teamId: string) {
    return this.prisma.team_members.findMany({
      where: { team_id: teamId },
      include: {
        users_team_members_user_idTousers: true,
      },
    });
  }

  async findByDesignation(designation: string) {
    return this.prisma.team_members.findMany({
      where: { designation: designation as any },
      include: {
        users_team_members_user_idTousers: true,
        teams: {
          include: {
            institutes: true,
          },
        },
      },
    });
  }

  async findPendingApprovals() {
    return this.prisma.team_members.findMany({
      where: { is_approved: false },
      include: {
        users_team_members_user_idTousers: true,
        teams: {
          include: {
            institutes: true,
          },
        },
      },
    });
  }

  async update(id: string, data: Prisma.team_membersUpdateInput) {
    return this.prisma.team_members.update({
      where: { id },
      data,
      include: {
        users_team_members_user_idTousers: true,
        teams: true,
      },
    });
  }

  async approve(id: string) {
    return this.prisma.team_members.update({
      where: { id },
      data: {
        is_approved: true,
        approved_at: new Date(),
      },
      include: {
        users_team_members_user_idTousers: true,
        teams: true,
      },
    });
  }

  async bulkApprove(ids: string[]) {
    return this.prisma.team_members.updateMany({
      where: {
        id: {
          in: ids,
        },
      },
      data: {
        is_approved: true,
        approved_at: new Date(),
      },
    });
  }

  async reject(id: string) {
    return this.prisma.team_members.delete({
      where: { id },
    });
  }

  async remove(id: string) {
    return this.prisma.team_members.delete({
      where: { id },
    });
  }

  async bulkRemove(ids: string[]) {
    return this.prisma.team_members.deleteMany({
      where: {
        id: {
          in: ids,
        },
      },
    });
  }

  async count(where?: Prisma.team_membersWhereInput) {
    return this.prisma.team_members.count({ where });
  }

  async getStats() {
    const [total, approved, pending, byDesignation] = await Promise.all([
      this.prisma.team_members.count(),
      this.prisma.team_members.count({ where: { is_approved: true } }),
      this.prisma.team_members.count({ where: { is_approved: false } }),
      this.prisma.team_members.groupBy({
        by: ['designation'],
        _count: {
          _all: true,
        },
      }),
    ]);

    return {
      total,
      approved,
      pending,
      byDesignation: byDesignation.map((item) => ({
        designation: item.designation,
        count: item._count._all,
      })),
    };
  }
}