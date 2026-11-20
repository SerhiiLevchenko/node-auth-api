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
  Delete,
  Param,
  ParseUUIDPipe,
  Ip,
  Headers,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';

import type { CookieOptions, Response } from 'express';

import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

import { CurrentUser } from './decorators/current-user.decorator';
import { AccessTokenGuard } from './guards/access-token.guard';
import type { AccessTokenPayload } from './types/jwt-payload.type';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,

    @Inject(ConfigService)
    private readonly config: ConfigService,
  ) {}

  private getRefreshCookieBaseOptions(): CookieOptions {
    const isProduction =
      this.config.getOrThrow<string>('NODE_ENV') === 'production';

    return {
      httpOnly: true,

      secure: isProduction,

      sameSite: 'lax',

      path: '/auth',
    };
  }

  private getRefreshCookieOptions(): CookieOptions {
    return {
      ...this.getRefreshCookieBaseOptions(),

      maxAge: this.config.getOrThrow<number>('JWT_REFRESH_TTL_SECONDS') * 1000,
    };
  }

  @Throttle({
    default: {
      limit: 5,
      ttl: 60_000,
    },
  })
  @Post('register')
  register(@Body() body: RegisterDto) {
    return this.authService.register(body.email, body.password);
  }

  @Throttle({
    default: {
      limit: 5,
      ttl: 60_000,
    },
  })
  @HttpCode(200)
  @Post('login')
  async login(
    @Body()
    body: LoginDto,
    @Ip()
    ip: string,
    @Headers('user-agent')
    userAgent: string | undefined,
    @Res({ passthrough: true })
    response: Response,
  ) {
    const user = await this.authService.validateUser(body.email, body.password);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const { sessionId, refreshToken } = await this.authService.createSession(
      user,
      {
        ip,
        userAgent,
      },
    );

    const accessToken = this.authService.createAccessToken(user, sessionId);

    response.cookie(
      'refreshToken',
      refreshToken,
      this.getRefreshCookieOptions(),
    );

    return {
      user: {
        id: user.id,
        email: user.email,
      },
      accessToken,
    };
  }

  @Throttle({
    default: {
      limit: 20,
      ttl: 60_000,
    },
  })
  @HttpCode(200)
  @Post('refresh')
  async refresh(
    @Req()
    request: {
      cookies?: {
        refreshToken?: string;
      };
    },
    @Ip()
    ip: string,
    @Headers('user-agent')
    userAgent: string | undefined,
    @Res({ passthrough: true }) response: Response,
  ) {
    const refreshToken = request.cookies?.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }

    try {
      const result = await this.authService.validateRefreshToken(refreshToken);

      if (!result) {
        throw new UnauthorizedException('Refresh token is invalid or expired');
      }

      const { user, session } = result;

      const accessToken = this.authService.createAccessToken(user, session.id);

      const newRefreshToken = this.authService.rotateRefreshToken(
        user,
        session.id,
        {
          ip,
          userAgent,
        },
      );

      response.cookie(
        'refreshToken',
        newRefreshToken,
        this.getRefreshCookieOptions(),
      );

      return {
        accessToken,
      };
    } catch {
      throw new UnauthorizedException('Refresh token is invalid or expired');
    }
  }

  @UseGuards(AccessTokenGuard)
  @Post('logout')
  @HttpCode(204)
  async logout(
    @CurrentUser()
    user: AccessTokenPayload,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.logout(user.sub, user.sid);

    response.clearCookie('refreshToken', this.getRefreshCookieBaseOptions());
  }

  @UseGuards(AccessTokenGuard)
  @Get('sessions')
  getSessions(
    @CurrentUser()
    user: AccessTokenPayload,
  ) {
    return this.authService.getSessions(user.sub, user.sid);
  }

  @UseGuards(AccessTokenGuard)
  @Delete('sessions/:id')
  @HttpCode(204)
  async deleteSession(
    @Param('id', new ParseUUIDPipe({ version: '4' }))
    sessionId: string,

    @CurrentUser()
    user: AccessTokenPayload,
  ) {
    await this.authService.deleteSession(user.sub, sessionId, user.sid);
  }

  @UseGuards(AccessTokenGuard)
  @Post('logout-all')
  @HttpCode(204)
  async logoutAll(
    @CurrentUser()
    user: AccessTokenPayload,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.authService.logoutAll(user.sub);

    response.clearCookie('refreshToken', this.getRefreshCookieBaseOptions());
  }
}
