import {
  Body,
  Controller,
  Post,
  Get,
  Req,
  Res,
  Inject,
  UnauthorizedException,
  UseGuards,
  HttpCode,
} from '@nestjs/common';

import type { Response } from 'express';

import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { AuthGuard, JwtPayload } from './auth.guard';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
  ) {}

  @Post('register')
  register(@Body() body: RegisterDto) {
    return this.authService.register(body.email, body.password);
  }

  @Post('login')
  async login(
    @Body()
    body: LoginDto,
    @Res({ passthrough: true })
    response: Response,
  ) {
    const user = await this.authService.validateUser(body.email, body.password);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const accessToken = this.authService.createAccessToken(user);

    const refreshToken = this.authService.createRefreshToken(user);

    await this.authService.saveRefreshToken(user.id, refreshToken);

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      user: {
        id: user.id,
        email: user.email,
      },
      accessToken,
    };
  }

  @UseGuards(AuthGuard)
  @Get('me')
  getMe(
    @Req()
    request: {
      user: JwtPayload;
    },
  ) {
    return {
      id: request.user.sub,
      email: request.user.email,
    };
  }

  @Post('refresh')
  async refresh(
    @Req()
    request: {
      cookies?: {
        refreshToken?: string;
      };
    },
    @Res({ passthrough: true }) response: Response,
  ) {
    const refreshToken = request.cookies?.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }

    try {
      const user = await this.authService.validateRefreshToken(refreshToken);

      if (!user) {
        throw new UnauthorizedException('Refresh token is invalid or expired');
      }

      const accessToken = this.authService.createAccessToken(user);

      const newRefreshToken = this.authService.createRefreshToken(user);

      await this.authService.saveRefreshToken(user.id, newRefreshToken);

      response.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return {
        accessToken,
      };
    } catch {
      throw new UnauthorizedException('Refresh token is invalid or expired');
    }
  }

  @UseGuards(AuthGuard)
  @Post('logout')
  @HttpCode(204)
  async logout(
    @Req()
    request: {
      user: JwtPayload;
    },
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.logout(request.user.sub);

    response.clearCookie('refreshToken', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
    });
  }
}
