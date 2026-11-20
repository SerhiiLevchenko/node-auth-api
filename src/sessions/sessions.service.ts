import { Inject, Injectable } from '@nestjs/common';

import { PrismaService } from '../prisma/prisma.service';
import type { SessionMetadata } from './types/session-metadata.type';

@Injectable()
export class SessionsService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: PrismaService,
  ) {}

  create(
    data: {
      id: string;
      userId: number;
      refreshTokenHash: string;
      expiresAt: Date;
    },
    metadata: SessionMetadata,
  ) {
    return this.prisma.session.create({
      data: {
        ...data,
        ip: metadata.ip,
        userAgent: metadata.userAgent,
        lastUsedAt: new Date(),
      },
    });
  }

  findById(id: string) {
    return this.prisma.session.findUnique({
      where: {
        id,
      },
    });
  }

  updateRefreshToken(
    id: string,
    refreshTokenHash: string,
    expiresAt: Date,
    metadata: SessionMetadata,
  ) {
    return this.prisma.session.update({
      where: {
        id,
      },
      data: {
        refreshTokenHash,
        expiresAt,
        ip: metadata.ip,
        userAgent: metadata.userAgent,
        lastUsedAt: new Date(),
      },
    });
  }

  deleteByIdAndUserId(id: string, userId: number) {
    return this.prisma.session.deleteMany({
      where: {
        id,
        userId,
      },
    });
  }

  findAllByUserId(userId: number) {
    return this.prisma.session.findMany({
      where: {
        userId,
        expiresAt: {
          gt: new Date(),
        },
      },
      select: {
        id: true,
        ip: true,
        userAgent: true,
        lastUsedAt: true,
        createdAt: true,
        updatedAt: true,
        expiresAt: true,
      },
      orderBy: {
        lastUsedAt: 'desc',
      },
    });
  }

  deleteAllByUserId(userId: number) {
    return this.prisma.session.deleteMany({
      where: {
        userId,
      },
    });
  }
}
