import { Request, Response } from 'express';
import prisma from '../models/user';
import { comparePasswords, hashPassword } from '../services/password.service';
import { generateToken } from '../services/auth.service';
import { error } from 'console';


export const register = async (req: Request, res: Response): Promise<void> => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            const missingFields = [];
            if (!email) missingFields.push('email');
            if (!password) missingFields.push('password');

            res.status(400).json({ message: `Faltan los siguientes campos: ${missingFields.join(', ')}` });
            return;
        }

        const hashedPassword = await hashPassword(password);

        const user = await prisma.create({
            data: {
                email,
                password: hashedPassword
            }
        });

        const token = generateToken(user);
        res.status(201).json({ token });

    } catch (error : any) {
        if(error?.code === 'P2002' && error?.meta?.target?.includes('email')) {
            res.status(400).json({ error: 'El email ingresado ya existe' });
        }
    }
};

export const login = async ( req: Request, res: Response) => {
    const { email, password } = req.body

    try {

        if (!email || !password) {
            const missingFields = [];
            if (!email) missingFields.push('email');
            if (!password) missingFields.push('password');

            res.status(400).json({ message: `Faltan los siguientes campos: ${missingFields.join(', ')}` });
            return;
        }
        
        const user = await prisma.findUnique({ where: { email } })

        if(!user) {
            res.status(404).json({ error: 'Usuario no encontrado' })
            return
        }

        const passwordMatch = await comparePasswords(password, user.password);

        if(!passwordMatch) {
            res.status(401).json({ error: 'Usuario y contrasea no coinciden' })
        }

        const token = generateToken(user)
        res.status(200).json({ token })

    } catch (error) {
        console.log('Error ', error)
    }
}
