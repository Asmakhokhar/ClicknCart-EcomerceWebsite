const generatedOtp = () =>{
    return Math.floor(100000 + Math.random() * 900000).toString();
}
export default generatedOtp;