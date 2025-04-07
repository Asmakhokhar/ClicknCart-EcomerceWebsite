import { Router } from "express";
import {registerUserController, verifyEmailController, loginController} from "../Controllers/user.controller.js";


const userRouter = Router();
userRouter.post('/register', registerUserController)
userRouter.post('/verify', verifyEmailController)
userRouter.post('/login', loginController)

export default userRouter;