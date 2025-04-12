import { Router } from "express";
import {registerUserController, verifyEmailController, loginController,logoutController,uploadAvatar,updateUserDetails,forgetPasswordController,resetPasswordController,resetPassword,refreshToken} from "../Controllers/user.controller.js";
import auth from "../middleware/auth.js";
import upload from "../middleware/multer.js";


const userRouter = Router();
userRouter.post('/register', registerUserController)
userRouter.post('/verify', verifyEmailController)
userRouter.post('/login', loginController)
userRouter.get('/logout', auth,logoutController )
userRouter.put('/upload-avatar',auth,upload.single('avatar'),uploadAvatar)
userRouter.put('/update-user',auth,updateUserDetails)
userRouter.put('/forgot-password',forgetPasswordController)
userRouter.put('/verify-forgot-password-otp',resetPasswordController)
userRouter.put('/reset-password',resetPassword)
userRouter.post('/refreshToken',refreshToken)

export default userRouter;