import { ConflictException, Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';

import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    @Inject(UsersService)
    private readonly usersService: UsersService,

    @Inject(JwtService)
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string) {
    // 1. Знаходимо користувача за email
    const user = await this.usersService.findByEmail(email);

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
    // 1. Знаходимо користувача за email
    const existingUser = await this.usersService.findByEmail(email);

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const passwordHash = await argon2.hash(password);

    const user = await this.usersService.create(email, passwordHash);

    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };
  }

  async logout(userId: number) {
    await this.usersService.updateRefreshTokenHash(userId, null);
  }

  createAccessToken(user: { id: number; email: string }) {
    const payload = {
      sub: user.id,
      email: user.email,
    };

    return this.jwtService.sign(payload);
  }

  createRefreshToken(user: { id: number; email: string }) {
    const payload = {
      sub: user.id,
      email: user.email,
    };

    return this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });
  }

  async validateRefreshToken(token: string) {
    const payload = await this.jwtService.verifyAsync<{
      sub: number;
      email: string;
    }>(token, {
      secret: process.env.JWT_REFRESH_SECRET,
    });

    const user = await this.usersService.findById(payload.sub);

    if (!user || !user.refreshTokenHash) {
      return null;
    }

    const tokenMatches = await argon2.verify(user.refreshTokenHash, token);

    if (!tokenMatches) {
      return null;
    }

    return user;
  }

  async saveRefreshToken(userId: number, refreshToken: string) {
    const refreshTokenHash = await argon2.hash(refreshToken);

    await this.usersService.updateRefreshTokenHash(userId, refreshTokenHash);
  }
}
