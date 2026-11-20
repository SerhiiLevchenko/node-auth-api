import {
  ConflictException,
  Injectable,
  Inject,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { randomUUID } from 'node:crypto';

import { UsersService } from '../users/users.service';
import { SessionsService } from '../sessions/sessions.service';

import { ConfigService } from '@nestjs/config';
import { RefreshTokenPayload } from './types/jwt-payload.type';

import type { Role } from '../generated/prisma/enums.js';
import { Prisma } from '../generated/prisma/client.js';
import { SessionMetadata } from '../sessions/types/session-metadata.type';

@Injectable()
export class AuthService {
  constructor(
    @Inject(UsersService)
    private readonly usersService: UsersService,

    @Inject(JwtService)
    private readonly jwtService: JwtService,

    @Inject(SessionsService)
    private readonly sessionsService: SessionsService,

    @Inject(ConfigService)
    private readonly config: ConfigService,
  ) {}

  private getRefreshTokenExpiresAt() {
    const ttlSeconds = this.config.getOrThrow<number>(
      'JWT_REFRESH_TTL_SECONDS',
    );

    return new Date(Date.now() + ttlSeconds * 1000);
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  async validateUser(email: string, password: string) {
    const normalizedEmail = this.normalizeEmail(email);
    // 1. Знаходимо користувача за email
    const user = await this.usersService.findByEmail(normalizedEmail);

    if (!user) {
      return null;
    }

    // 2. Перевіряємо, чи правильний пароль
    const passwordIsValid = await argon2.verify(user.passwordHash, password);

    // 3. Якщо пароль неправильний — відмовляємо
    if (!passwordIsValid) {
      return null;
    }

    return user;
  }

  async register(email: string, password: string) {
    const normalizedEmail = this.normalizeEmail(email);

    const passwordHash = await argon2.hash(password);

    try {
      const user = await this.usersService.create(
        normalizedEmail,
        passwordHash,
      );

      return {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      };
    } catch (error: unknown) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('User with this email already exists');
      }

      throw error;
    }
  }

  async logout(userId: number, sessionId: string) {
    await this.sessionsService.deleteByIdAndUserId(sessionId, userId);
  }

  createAccessToken(
    user: { id: number; email: string; role: Role },
    sessionId: string,
  ) {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
      sid: sessionId,
      role: user.role,
    });
  }

  createRefreshToken(user: { id: number; email: string }, sessionId: string) {
    return this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        sid: sessionId,
        jti: randomUUID(),
      },
      {
        secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.config.getOrThrow<number>('JWT_REFRESH_TTL_SECONDS'),
      },
    );
  }

  async createSession(
    user: { id: number; email: string },
    metadata: SessionMetadata,
  ) {
    const sessionId = randomUUID();

    const refreshToken = this.createRefreshToken(user, sessionId);

    const refreshTokenHash = await argon2.hash(refreshToken);

    const expiresAt = this.getRefreshTokenExpiresAt();

    await this.sessionsService.create(
      {
        id: sessionId,
        userId: user.id,
        refreshTokenHash,
        expiresAt,
      },
      metadata,
    );

    return {
      sessionId,
      refreshToken,
    };
  }

  async rotateRefreshToken(
    user: {
      id: number;
      email: string;
    },
    sessionId: string,
    metadata: SessionMetadata,
  ) {
    const refreshToken = this.createRefreshToken(user, sessionId);

    const refreshTokenHash = await argon2.hash(refreshToken);

    const expiresAt = this.getRefreshTokenExpiresAt();

    await this.sessionsService.updateRefreshToken(
      sessionId,
      refreshTokenHash,
      expiresAt,
      metadata,
    );

    return refreshToken;
  }

  async getSessions(userId: number, currentSessionId?: string) {
    const sessions = await this.sessionsService.findAllByUserId(userId);

    return sessions.map((session) => ({
      ...session,
      current: session.id === currentSessionId,
    }));
  }

  async validateRefreshToken(token: string) {
    const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(
      token,
      {
        secret: this.config.getOrThrow<string>('JWT_REFRESH_SECRET'),
      },
    );

    if (!payload.sid) {
      return null;
    }

    const session = await this.sessionsService.findById(payload.sid);

    if (!session) {
      return null;
    }

    if (session.userId !== payload.sub) {
      return null;
    }

    if (session.expiresAt <= new Date()) {
      return null;
    }

    const tokenMatches = await argon2.verify(session.refreshTokenHash, token);

    if (!tokenMatches) {
      return null;
    }

    const user = await this.usersService.findById(payload.sub);

    if (!user) {
      return null;
    }

    return {
      user,
      session,
    };
  }

  async deleteSession(
    userId: number,
    sessionId: string,
    currentSessionId: string,
  ) {
    if (sessionId === currentSessionId) {
      throw new BadRequestException(
        'Use logout to terminate the current session',
      );
    }

    const result = await this.sessionsService.deleteByIdAndUserId(
      sessionId,
      userId,
    );

    if (result.count === 0) {
      throw new NotFoundException('Session not found');
    }
  }

  async logoutAll(userId: number) {
    await this.sessionsService.deleteAllByUserId(userId);
  }
}
