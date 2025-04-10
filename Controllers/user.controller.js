import ModelUser from "../models/user.model.js";
import bcrypt from "bcryptjs";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import sendEmail from "../Config/sendEmail.js";
import generatedAccessToken from "../utils/generateAccessToken.js";
import generateRefreshToken from "../utils/generateRefreshToken.js";

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