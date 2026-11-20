import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { AppModule } from '../src/app.module.js';
import { PrismaService } from '../src/prisma/prisma.service.js';

describe('Auth E2E', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();

    app.use(cookieParser());

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();

    prisma = app.get(PrismaService);
  });

  beforeEach(async () => {
    await prisma.session.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await app.close();
  });

  it('register -> login -> refresh -> sessions -> logout', async () => {
    const agent = request.agent(app.getHttpServer());

    const registerResponse = await agent
      .post('/auth/register')
      .send({
        email: ' TEST@Example.COM ',
        password: '123456',
      })
      .expect(201);

    expect(registerResponse.body.email).toBe('test@example.com');

    const loginResponse = await agent
      .post('/auth/login')
      .send({
        email: 'TEST@EXAMPLE.COM',
        password: '123456',
      })
      .expect(200);

    expect(loginResponse.body.accessToken).toEqual(expect.any(String));

    const firstAccessToken = loginResponse.body.accessToken;

    const sessionsResponse = await agent
      .get('/auth/sessions')
      .set('Authorization', `Bearer ${firstAccessToken}`)
      .expect(200);

    expect(sessionsResponse.body).toHaveLength(1);

    expect(sessionsResponse.body[0].current).toBe(true);

    const refreshResponse = await agent.post('/auth/refresh').expect(200);

    expect(refreshResponse.body.accessToken).toEqual(expect.any(String));

    const newAccessToken = refreshResponse.body.accessToken;

    await agent
      .post('/auth/logout')
      .set('Authorization', `Bearer ${newAccessToken}`)
      .expect(204);

    await agent.post('/auth/refresh').expect(401);
  });
});
