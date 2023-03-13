import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}

  async signup(dto: AuthDto) {
    //generate password
    const hash = await argon.hash(dto.password);

    try {
      //save new user in db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

    return this.signToken(user.id, user.email);

    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException(
          'Credentials taken!',
        );
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    //find the user by email
    const user = await this.prisma.user.findUnique({
        where: {
            email: dto.email,
        }
    })
    //throw exception if it not exist
    if(!user) throw new ForbiddenException('Credentials incorect!')

    //compare password
    const passMatches = await argon.verify(user.hash, dto.password)
    //if incorect password throw exception
    if(!passMatches) throw new ForbiddenException('Credentials incorect!')

    //send back the user
    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string): Promise<{access_token: string}>{
    const payload = {
      sub: userId,
      email
    }

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET')
    })

    return {
      access_token: token,
    }
  }
}
