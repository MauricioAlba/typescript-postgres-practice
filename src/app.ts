import dotenv from 'dotenv';
import express  from 'express';
import authRoutes from './routes/authRoutes'
import userRoutes from './routes/userRoutes'

dotenv.config();

const app = express();

app.use(express.json());

//Routes
app.use("/auth", authRoutes);
app.use("/user", userRoutes);

//Autenticacion

//User


export default app;