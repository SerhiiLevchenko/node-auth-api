import type { Role } from '../../generated/prisma/enums.ts';

type BaseTokenPayload = {
  sub: number;
  email: string;
  sid: string;
  iat?: number;
  exp?: number;
};

export type AccessTokenPayload = BaseTokenPayload & {
  role: Role;
};

export type RefreshTokenPayload = BaseTokenPayload & {
  jti: string;
};
