const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
var fetchuser = require('../middleware/fetchuser');


const JWT_SECRET = 'Sidishere$is';

// ROUTE 1: Create a User using: POST "/api/auth/createsuser". No login required
router.post('/createsuser', [
    body('name','Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must be atleast 5 characters').isLength({ min: 5 }),
], async (req,res)=>{

    //If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    //Check whether the user exists alredy with this email
try{
    
    let user = await User.findOne({email: req.body.email});
    if(user){
        return res.status(400).json({error: "Sorry a user with this email already exists"})
    }

    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password, salt) ;

    //Create a new user
    user = await User.create({
        name: req.body.name ,
        email: req.body.email,
        password: secPass,
    })

    const data = {
        user : {
            id: user.id
        }
    }

    const  authtoken = jwt.sign(data,JWT_SECRET);

    res.json({authtoken});


} catch(error){
    console.error(error.message);
    res.status(500).send("Some error occured");
}
    
});

//ROUTE 2: Authenticate a User using: POST "/api/auth/login". No login required

router.post('/login', [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must be atleast 5 characters').exists(),
], async (req,res)=>{

    //If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {email, password} = req.body;

    try {
        let user = await User.findOne({email});
        if(!user){
            return res.status(400).json({error: "Please try to login with correct credentials"});
        }
        const passwordCompare = await bcrypt.compare(password, user.password);
        if(!passwordCompare){
            return res.status(400).json({error: "Please try to login with correct credentials"});
        }

        const data = {
            user : {
                id: user.id
            }
        }
    
        const  authtoken = jwt.sign(data,JWT_SECRET);

        res.json({authtoken});

    } catch (error) {
        console.error(error.message);
        res.status(500).send("Interanl Server Error");
    }
    
});


//ROUTE 2: Get loggedin User Details using: POST "/api/auth/getuser". login required
router.post('/getuser', fetchuser, async (req,res)=>{
try {

    userId = req.user.id;
    const user = await User.findById(userId).select("-password")
    res.send(user)
} catch (error) {
    console.error(error.message);
    res.status(500).send("Interanl Server Error");
}
});
module.exports = router;