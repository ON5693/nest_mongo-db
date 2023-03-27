import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { AuthService } from 'src/auth/auth.service';
import { Users } from './models/users.model';
import { SignupDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';

@Injectable()
export class UsersService {
    constructor(
        @InjectModel('Users')
        private readonly usersModel: Model<Users>,
        private readonly authService: AuthService,
    ) {}

    public async signUp(singUpDto: SignupDto): Promise<Users> {
        const user = new this.usersModel(singUpDto);

        return user.save();
    }

    public async signIn(singInDto: SigninDto): Promise<{ name: string, jwtToken: string, email: string }> {
        const user = await this.findByEmail(singInDto.email);
        const match = await this.checkPassword(singInDto.password, user);

        if(!match)
            throw new NotFoundException('Credencias inválidas');

        const jwtToken = await this.authService.createAccessToken(user._id);

        return { name: user.name, jwtToken, email: user.email };
    }

    public async findAll(): Promise<Users[]> {
        return this.usersModel.find();
    }

    public async findByEmail(email: string): Promise<Users> {
        const user = await this.usersModel.findOne({ email: email});

        if(!user)
            throw new NotFoundException('Email não encontrado');

        return user;
    }

    private async checkPassword(senha: string, user: Users): Promise<boolean> {
        const match = await bcrypt.compare(senha, user.password);

        if(!match)
            throw new NotFoundException('Senha não encontrado');

        return match;
    }
}
