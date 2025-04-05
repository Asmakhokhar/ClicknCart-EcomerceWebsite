import express, { request, response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import helmet from 'helmet'
import connectDB from './Config/connectDb.js';

dotenv.config();

const app = express()
app.use(cors({
   credentials : true,
   origin : process.env.FRONTEND_URL
}));
app.use(express.json())
app.use(cookieParser())
app.use(morgan('dev'))
app.use(helmet({
    crossOriginResourcePolicy : false
}))

const PORT = process.env.PORT || 8080;
app.get('/', (request, response) => {
    response.json({
        message : "Server is running" + PORT
    })
})
connectDB().then(() =>{
    app.listen(PORT,() => {
        console.log("Server is running on port",PORT)
    })
})

