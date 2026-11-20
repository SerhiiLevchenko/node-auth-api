import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import type { AccessTokenPayload } from '../types/jwt-payload.type';

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AccessTokenPayload => {
    const request = context.switchToHttp().getRequest<{
      user: AccessTokenPayload;
    }>();

    return request.user;
  },
);
