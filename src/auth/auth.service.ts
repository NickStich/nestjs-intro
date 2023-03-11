import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

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

      delete user.hash;

      //return the user
      return user;
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
    delete user.hash;
    return user;
  }
}
