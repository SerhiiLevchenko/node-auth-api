import {
  Controller,
  Get,
  Inject,
  NotFoundException,
  Param,
  ParseIntPipe,
  UseGuards,
} from '@nestjs/common';

import { Role } from '../generated/prisma/enums.js';

import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { AccessTokenGuard } from '../auth/guards/access-token.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import type { AccessTokenPayload } from '../auth/types/jwt-payload.type';

import { UsersService } from './users.service';

@Controller('users')
@UseGuards(AccessTokenGuard, RolesGuard)
export class UsersController {
  constructor(
    @Inject(UsersService)
    private readonly usersService: UsersService,
  ) {}

  @Get('me')
  async getMe(
    @CurrentUser()
    user: AccessTokenPayload,
  ) {
    const foundUser = await this.usersService.findPublicById(user.sub);

    if (!foundUser) {
      throw new NotFoundException('User not found');
    }

    return foundUser;
  }

  @Roles([Role.ADMIN])
  @Get()
  getAll() {
    return this.usersService.findAllPublic();
  }

  @Roles([Role.ADMIN])
  @Get(':id')
  async getById(
    @Param('id', ParseIntPipe)
    id: number,
  ) {
    const user = await this.usersService.findPublicById(id);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }
}
