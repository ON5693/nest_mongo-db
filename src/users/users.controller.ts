import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { SignupDto } from './dto/signup.dto';
import { Users } from './models/users.model';
import { SigninDto } from './dto/signin.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('users')
export class UsersController {
    constructor(
        private readonly usersService: UsersService,
    ) {}

    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    public async signup(
        @Body() signUpDto: SignupDto
    ): Promise<Users> {
        return this.usersService.signUp(signUpDto);
    }

    @Post('signin')
    @HttpCode(HttpStatus.OK)
    public async signin(
        @Body() signIpDto: SigninDto
    ): Promise<{ name: string, jwtToken: string, email: string }> {
        return this.usersService.signIn(signIpDto);
    }

    @Get()
    @UseGuards(AuthGuard('jwt'))
    @HttpCode(HttpStatus.OK)
    public async findAll(): Promise<Users[]> {
        return this.usersService.findAll();
    }
}
 