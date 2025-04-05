import mongoose from "mongoose";
import dotenv from 'dotenv'

dotenv.config();

if(!process.env.MONGODB_URI){
    throw new Error(
        "Please provide MONGODB_URI in the .env file"
    )
}
