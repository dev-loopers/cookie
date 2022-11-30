const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const UserModel = require('../models/UserModel');


const protectRoute =asyncHandler( async (req,resp,next)=>{
    let token;
    const cookie = req.headers.cookie;

        try {
           
            token = cookie.split("=")[1];
            const decode = jwt.verify(token,process.env.JWT_KEY);
           
            req.user = await UserModel.findById(decode.id).select('-password');
            next();
        } catch (error) {
            resp.status(404).json({message:"invalid token"});
            
        }
        if(!token || cookie.split("=")[1] == 'undefined'){
            resp.status(404).json({message:"Unauthorized access"});
        }
});


module.exports = {protectRoute};