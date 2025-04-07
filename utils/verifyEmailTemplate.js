const verifyEmailTemplate = ({name, url}) => {
    return`
    <html>
    <head>
    <title>Verify Email</title>
    <body>
    <h1>Verify Email</h1>
    <p>Dear ${name},</p>
    <p>Thank you for registering ClicknCart.<p>
    <p>To verify your email address, please click the link below:</P>
    <a href="${url}"> Verify Email</a>
    </body>

    `
}
export default verifyEmailTemplate