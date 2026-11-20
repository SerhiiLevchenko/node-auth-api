import { Reflector } from '@nestjs/core';

import type { Role } from '../../generated/prisma/enums.js';

export const Roles = Reflector.createDecorator<Role[]>();
