const asyncHandler = require('express-async-handler');
const UserModel = require('../models/UserModel');
const { generateToken } = require('../utils/webToken');
const jwt = require('jsonwebtoken');


async function usernameAvailable(username){
    const user = await UserModel.findOne({
            username
    });
    if (user && user !== null){
        return true;
    }else{
        return false;
    }

};

const usernameExist = asyncHandler( async (req,resp)=>{
    const {username} = req.body; 
    const data = await usernameAvailable(username);

    if(data && data !== null){
        resp.json({is_available:false});
    }else{
        resp.json({is_available:true});
    }
});


// register new user 
const registerUser = asyncHandler(async (req, resp) => {
    const { name, business,contact, email,address, username, password } = req.body;
    const userExist = await UserModel.findOne({
        $or: [
            { email },
            { username },
            { contact },
        ]
    });

    if (userExist) {
        resp.status(400);
        throw new Error("User already exist by email or username  or contact please use another email or contact or uswername")
    } else {
        const newUser = await UserModel.create({ name, contact, email, username, password });
        if (newUser) {
            resp.json({is_created :true,"user": newUser, "msg": "user created" });
        } else {
            resp.json({is_created :false, "msg": "user creation failed" });
        }
    }

});


// check user  authentication 
const authController = asyncHandler(async (req, resp) => {
    const { username, password } = req.body;
    const user = await UserModel.findOne({ "username":username });

    if (user && (await user.checkpassword(password))) {

        resp.cookie(String(user._id), generateToken(user._id), {
            path: '/',
            expires: new Date(Date.now() + 1000 * 60 * 60 *24 *15),
            httpOnly: true,
            sameSite: 'lax'
        });
        resp.status(200).json({message:"login done",is_done:true});
    } else {
        resp.status(404).json({ message: "Invalid Crediantial" ,is_done:false});
    }

});

// get user profile after authentication
const getProfile = asyncHandler(async (req, resp) => {
    const user = await UserModel.findById(req.user._id, "-password");
    if (user) {
        resp.json({
            user
        });

    } else {
        resp.status(404);
        throw new Error("User not found,please register with us")
    }

});

const refreshTocken = asyncHandler(async (req, resp, next) => {
    const cookie = req.headers.cookie;
    const prevToken = cookie.split("=")[1];
    if(!prevToken){
        return resp.status(400).json({ message: "Coudn't find authorization token" });
    }
  
        
            const decode = jwt.verify(prevToken, process.env.JWT_KEY);
            resp.clearCookie(`${decode.id}`);
            req.cookies[`${decode.id}`] = "";
        
            resp.cookie(String(decode.id), generateToken(decode.id), {
                path: '/',
                expires: new Date(Date.now() + 1000 * 35),
                httpOnly: true,
                sameSite: 'lax'
            });
            req.user = await UserModel.findById(decode.id).select('-password');

  

    next();



});

// logout 
const logout =  asyncHandler( async (req,resp)=>{
    const cookie = req.headers.cookie;
    const prevToken = cookie.split("=")[1];
    if (!prevToken) {
        return resp.status(400).json({ message: "token not available" });
        
    }
    const decode = jwt.verify(prevToken, process.env.JWT_KEY);
    resp.clearCookie(`${decode.id}`);
    req.cookies[`${decode.id}`] = "";
    return resp.status(400).json({is_logged_out:true});

});

module.exports = { authController, getProfile, registerUser, refreshTocken ,logout,usernameExist,usernameAvailable};