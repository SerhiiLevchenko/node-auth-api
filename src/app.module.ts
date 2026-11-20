import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';

import {
  ThrottlerGuard,
  ThrottlerModule,
  getOptionsToken,
  getStorageToken,
} from '@nestjs/throttler';

import type {
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import { APP_GUARD, Reflector } from '@nestjs/core';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { envSchema } from './config/env.schema';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: envSchema,
    }),
    AuthModule,
    UsersModule,
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => [
        {
          ttl: config.getOrThrow<number>('RATE_LIMIT_TTL_MS'),
          limit: config.getOrThrow<number>('RATE_LIMIT_LIMIT'),
        },
      ],
    }),
  ],
  controllers: [AppController],
  providers: [
    AppService,
    Reflector,
    {
      provide: APP_GUARD,
      useFactory: (
        options: ThrottlerModuleOptions,
        storage: ThrottlerStorage,
        reflector: Reflector,
      ) => new ThrottlerGuard(options, storage, reflector),
      inject: [getOptionsToken(), getStorageToken(), Reflector],
    },
  ],
})
export class AppModule {}
