import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Request } from 'express';
import { sign } from 'jsonwebtoken';
import { Model } from 'mongoose';
import { Users } from 'src/users/models/users.model';
import { JwtPayload } from './models/jwt-payload.model';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel('Users')
        private readonly usersModel: Model<Users>,
    ) { }

    public async createAccessToken(userId: string): Promise<string> {
        return sign({ userId }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRATION,
        })
    }

    public async validateUser(jwtPayload: JwtPayload): Promise<Users> {
        const user = await this.usersModel.findOne({ _id: jwtPayload.userId});

        if(!user)
            throw new UnauthorizedException('Usuário não encontrado');

        return user;
    }

    private static jwtExtractor(request: Request): string {
        const authHeader = request.headers.authorization;

        if(!authHeader)
            throw new BadRequestException('Token não enviado');

        const[type, token] = authHeader.split(' ');

        return token;
    }

    public returnJwtExtractor(): (request: Request) => string {
        return AuthService.jwtExtractor;
    }
}
