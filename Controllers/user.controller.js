import ModelUser from "../models/user.model.js";
import bcrypt from "bcryptjs";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import sendEmail from "../Config/sendEmail.js";
import generatedAccessToken from "../utils/generateAccessToken.js";
import generateRefreshToken from "../utils/generateRefreshToken.js";
import uploadImageCloudinary from "../utils/uploadimageCloudatry.js";
import generatedOtp from "../utils/generateOtp.js";
import forgotPasswordTemplate from "../utils/forgotPasswordTemplate.js";
import jwt from 'jsonwebtoken'


/// REGISTER CONTROLLER

export async function registerUserController(request, response) {
    try {
        const { name, email, password } = request.body;
        if(!name || !email || !password){
            return response.status(400).json({  
                message : "Provide name, email, password",
                error : true,
                success : false
            })
        }

        const user = await ModelUser.findOne({email})
        if(user){
            return response.json({
                message : "User already registered",
                error : true,
                success : false
            })
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt)

        const payload = {
            name,
            email,
            password : hashedPassword
        }
        const newUser = new ModelUser(payload)
        const save = await newUser.save()

        const verifyEmailUrl = `${process.env,FRONTEND_URL}/verify-email?code=${save?._id}`
        const verifyEmail = await sendEmail({
            sendTo : email,
            subject : "Verify Email from ClicknCart",
            html : verifyEmailTemplate({
                name,
                url : verifyEmailUrl
            })
        })

        return response.json({
            message : "User registered successfully",
            error : false,
            success : true,
            data : save,
        })

        
         

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
}

export async function verifyEmailController(request,response) {
    try {
        const { code} = request.body
        const user = await ModelUser.findOne({ _id : code})
        if (!user) {
            return response.status(400).json({
                message : "Invalid varification code",
                error : true,
                success : false
            })
        }

        const updateUser = await ModelUser.updateOne({_id : code},{
            verify_email : true
        })

        return response.json({
            message : "Verified Email",
            success : true,
            error : false

        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
    
}


// LOGIN CONTROLLER

export async function loginController(request, response) {
    try {
        const { email, password} = request.body

        if(!email || !password){
            return response.status(400).json({
                message : "Provide email, password",
                error : true,
                success : false
            })
        }
        const user = await ModelUser.findOne({ email})

        if(!user){
            return response.status(400).json({
                message : "User not Registerd",
                error : true,
                success : false
            })
        }
        if(user.status !== "Active"){
            return response.status(400).json({
                message : "Contact to Admin",
                error : true,
                success : false
            })
        }

        const isPasswordMatched = await bcrypt.compare(password, user.password)
        if(!isPasswordMatched){
            return response.status(400).json({
                message : "Check your password",
                error : true,
                success : false
            })
        }

        const accessToken = await generatedAccessToken(user._id)
        const refreshToken = await generateRefreshToken(user._id)
        
        const cookieOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.cookie("accessToken", accessToken, cookieOption)
        response.cookie("refreshToken", refreshToken, cookieOption)

        return response.json({
            message : "Login Successfully",
            error : false,
            success : true,
            data : {
                accessToken,
                refreshToken
            }
        })
        
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
    
}


// LOGOUT CONTROLLER 

export async function logoutController(request, response) {
    try {


        const userid = request.userId
        const cookieOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.clearCookie("accessToken",cookieOption)
        response.clearCookie("refreshToken",cookieOption) 

        const removeRefreshToken = await ModelUser.findByIdAndUpdate(userid, {
            refresh_token : ""
        })

        return response.json({
            message : "Logout successfully",
            error : false,
            success : true
        })

        
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
    
}

// Upload User Avatar 

export async function uploadAvatar(request, response) {
    try {

        const userId = request.userId
        const image = request.file

        const upload = await uploadImageCloudinary(image)

        const updateUser = await ModelUser.findByIdAndUpdate(userId, {
            avatar : upload.url
        })

        return response.json({
            message : "Image uploaded successfully",
            data : {
                _id : userId,
                avatar : upload.url
            }
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
}


// UPDATE USER DETAILS


export async function updateUserDetails(request,response) {
    try {
        const userId = request.userId
        const {name, email , password, mobile} = request.body

        let hashedPassword = ""

        if(password){
            const salt = await bcrypt.genSalt(10)
            hashedPassword = await bcrypt.hash(password, salt)
        }

        const updateUser = await ModelUser.updateOne({ _id : userId},{
            ...(name && { name : name}),
            ...(email && { email : email}),
            ...(mobile && {mobile : mobile}),
            ...(password && { password : hashedPassword})
        })

        return response.json({
            message : "Profile Updated Successfully",
            error : false,
            success : true,
            data : updateUser
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
    
}

// FORGET PASSWORD NOT LOGIN 

export async function forgetPasswordController(request, response) {
    try {
        const { email} = request.body

        const user = await ModelUser.findOne({email})
         if(!user){
            return response.status(400).json({
                message : "Email not availbale",
                error : true,
                success : false
             })
         }

         const otp = generatedOtp()
         const expireOtp = new Date() + 60 * 60 * 1000

          const update = await ModelUser.findByIdAndUpdate(user._id,{
            forgot_password_otp : otp,
            forgot_password_expiry : new Date(expireOtp).toISOString()
          })

          await sendEmail({
            sendTo : email,
            subject : "Reset Password from ClicknCart",
            html : forgotPasswordTemplate({
                name : user.name,
                otp : otp
            })
          })
           return response.json({
            message : "check your email",
            error : false,
            success : true
           })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
    
}

// RESET PASSWORD

export async function resetPasswordController(request, response){
    try {

         const { email, otp} = request.body

         if(!email || !otp){
            return response.json({
                message : "Provide required fields email,otp",
                error : true,
                success : false
            })
         }

        const user = await ModelUser.findOne({email})
         if(!user){
            return response.status(400).json({
                message : "Email not availbale",
                error : true,
                success : false
             })
         }

         const currentTime = new Date().toISOString

         if(user.forgot_password_expiry < currentTime){
            return response.status(400).json({
                message : "OTP is expired",
                error : true,
                success : false
            })
         }

         if(otp !== user.forgot_password_otp){
            return response.status(400).json({
                message : "Wrong OTP",
                error : true,
                success : false
            })
         }

         return response.json({
            message : "Verified Successfully",
            error : false,
            success : true
         })

    } catch (error) {
        return response.json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
}


// UPDATE PASSWORD

export async function resetPassword(request, response) {
    try {
        const {email, newPassword, conformPassword} = request.body
        if(!email || !newPassword || !conformPassword){
            return response.status(400).json({
                message : "Provide required fields email, newPassword, conformPassword"
            })
        }

        const user = await ModelUser.findOne({email})
        
        if(!user){
            return response.status(400).json({
                message : "Email not available",
                error : true,
                success : false
            })
        }

        if(newPassword !== conformPassword){
            return response.status(400).json({
                message : "newPassword and conform password are not same",
                error : true,
                success : false
            })
        }

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(newPassword,salt)

        const update = await ModelUser.findOneAndUpdate(user._id,{
            password :hashedPassword
        })

        return response.json({
            message : "Password Updated Successfully",
            error : false,
            success : true
        })
    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
    
}


// REFRESH TOKEN CONTROLLER 


export async function refreshToken(request,response) {
    try {
        const refreshToken = request.cookies.refreshToken || request?.headers?.authorization.split(" ")[1]

        if(!refreshToken){
            return response.status(400).json({
                message : "Refresh token not available",
                error : true,
                success : false
            })
        }


        const verifyToken = await jwt.verify(refreshToken,process.env.SECRET_KEY_REFRESH_TOKEN)

        if(!verifyToken){
            return response.status(401).json({
                message : "token is expired",
                error : true,
                success : false
            })
        }

        const userId = verifyToken._id
        const newAccessToken = await generatedAccessToken(userId)

        const cookieOption = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }
        response.cookie('accessToken',newAccessToken,cookieOption)

        return response.json({
            message : "newAccessToken is generated",
            error : false,
            success : true,
            data : {
                accessToken : newAccessToken
            }
        })

    } catch (error) {
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
    
}