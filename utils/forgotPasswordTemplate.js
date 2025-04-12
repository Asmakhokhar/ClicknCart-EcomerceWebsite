const forgotPasswordTemplate = ({name, otp}) =>{
    return`
    <div>
    <h1>Dear ${name},</h1>
    <p>you are requested to reset your password.Please use following otp code to reset your password.</p>
    <h2>${otp}</h2>
    <p>This OTP is valid for 1 hour only.Enter this otp to ClicknCart website to proceed with resetting your password.</p>
    <br>
    <br>
    <p>Thank You</p>
    <p>ClicknCart</p>
    </div>
    `
}

export default forgotPasswordTemplate