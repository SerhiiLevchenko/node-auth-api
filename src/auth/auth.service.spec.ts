import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as argon2 from 'argon2';
import type { ConfigService } from '@nestjs/config';
import type { JwtService } from '@nestjs/jwt';

import { Role } from '../generated/prisma/enums.js';
import type { SessionsService } from '../sessions/sessions.service';
import type { UsersService } from '../users/users.service';

import { AuthService } from './auth.service';

vi.mock('argon2', () => ({
  hash: vi.fn(),
  verify: vi.fn(),
}));

describe('AuthService', () => {
  let authService: AuthService;

  let usersService: {
    findByEmail: ReturnType<typeof vi.fn>;
  };

  let jwtService: {
    sign: ReturnType<typeof vi.fn>;
    verifyAsync: ReturnType<typeof vi.fn>;
  };

  let sessionsService: Record<string, ReturnType<typeof vi.fn>>;

  let configService: {
    getOrThrow: ReturnType<typeof vi.fn>;
  };

  const user = {
    id: 1,
    email: 'test@example.com',
    passwordHash: 'hashed-password',
    role: Role.USER,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(() => {
    usersService = {
      findByEmail: vi.fn(),
    };

    jwtService = {
      sign: vi.fn(),
      verifyAsync: vi.fn(),
    };

    sessionsService = {};

    configService = {
      getOrThrow: vi.fn(),
    };

    authService = new AuthService(
      usersService as unknown as UsersService,
      jwtService as unknown as JwtService,
      sessionsService as unknown as SessionsService,
      configService as unknown as ConfigService,
    );

    vi.clearAllMocks();
  });

  it('returns user when credentials are valid', async () => {
    usersService.findByEmail.mockResolvedValue(user);

    vi.mocked(argon2.verify).mockResolvedValue(true);

    const result = await authService.validateUser('TEST@EXAMPLE.COM', '123456');

    expect(usersService.findByEmail).toHaveBeenCalledWith('test@example.com');

    expect(argon2.verify).toHaveBeenCalledWith(user.passwordHash, '123456');

    expect(result).toEqual(user);
  });

  it('returns null when user does not exist', async () => {
    usersService.findByEmail.mockResolvedValue(null);

    const result = await authService.validateUser(
      'missing@example.com',
      '123456',
    );

    expect(result).toBeNull();

    expect(argon2.verify).not.toHaveBeenCalled();
  });

  it('returns null when password is invalid', async () => {
    usersService.findByEmail.mockResolvedValue(user);

    vi.mocked(argon2.verify).mockResolvedValue(false);

    const result = await authService.validateUser(
      'test@example.com',
      'wrong-password',
    );

    expect(result).toBeNull();
  });

  it('creates access token with user and session data', () => {
    jwtService.sign.mockReturnValue('access-token');

    const result = authService.createAccessToken(user, 'session-123');

    expect(jwtService.sign).toHaveBeenCalledWith({
      sub: user.id,
      email: user.email,
      role: user.role,
      sid: 'session-123',
    });

    expect(result).toBe('access-token');
  });
});
