const express= require('express');
const path= require('path');
const bodyParser= require('body-parser');
const mongoose=require('mongoose');
const User=require('./model/user');
const bcrypt=require('bcryptjs');
const jwt = require('jsonwebtoken');
const { StreamDescription } = require('mongodb');
require("dotenv").config();


const JWT_SECRET=process.env.JWT_SECRET;

var MONGODB_URL = process.env.MONGODB_URL;
mongoose.connect(MONGODB_URL).then(() => {
	//don't show the log when it is test
	if(process.env.NODE_ENV !== "test") {
		console.log("Connected to %s", MONGODB_URL);
		console.log("App is running ... \n");
		console.log("Press CTRL + C to stop the process. \n");
	}
})
	.catch(err => {
		console.error("App starting error:", err.message);
		process.exit(1);
	});

const app=express();
app.use('/', express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

app.get('/usersList', function(req, res) { 
    User.find({}, function(err, users) { 
        var userMap = {}; 
        users.forEach(function(user) { 
            userMap[user._id] = user; 
        }); 
    res.send(userMap); 
    }); 
});



app.post('/api/login', async(req,res)=>{
    const {username, password}=req.body;
    const user=await User.findOne({username}).lean();

    if(!user)
    {
        return res.json({status: 'error', error: 'Invalid username/password'});
    }
    if(await bcrypt.compare(password, user.password)){
        //username, password combination is successful

        const token=jwt.sign({
            id: user._id, 
            username: user.username
        },JWT_SECRET);

        return res.json({status: 'ok', data: token});
    }
    res.json({status: 'error', error: 'Invalid username/password'});
});


app.post('/api/register', async(req,res)=>{
    const {username, password: plainTextPassword}=req.body;

    if(!username || typeof username !== 'string'){
        return res.json({status: 'error', error:'Invalid username'});
    }

    if(!plainTextPassword || typeof plainTextPassword !== 'string'){
        return res.json({status: 'error', error:'Invalid password'});
    }

    if(plainTextPassword.length < 5){
        return res.json({
            status: 'error', 
            error:'Password too small. Should be atleast 6'
        });
    }

    const password= await bcrypt.hash(plainTextPassword, 10);

    try{
        const response= await User.create({
            username,
            password
        })
        console.log('User created succesfully: ', response);
    }catch(error){
        if(error.code===11000) //duplicate key
        {
            return res.json({status:'error', error:'Username already in use'});
    }
    throw error;
}
    res.json({status:'ok'})
});

app.listen(9999, ()=>{
    console.log('Server listening at 9999')
});
