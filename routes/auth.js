const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

// Create a User using: POST "/api/auth/createsuser". No login required
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
    user = await User.create({
        name: req.body.name ,
        email: req.body.email,
        password: req.body.password,
    })

    res.json({user});
} catch(error){
    console.error(error.message);
    res.status(500).send("Some error occured");
}
   
})

module.exports = router;