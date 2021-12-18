const express = require('express');
const router = express.Router();
const fetchuser = require('../middleware/fetchuser');
const Note = require('../models/Note');
const { body, validationResult } = require('express-validator');


//ROUTE 1: Get All the Notes using: GET "/api/notes/fetchallnotes". login required
router.get('/fetchallnotes', fetchuser, async (req,res)=>{
    try {
        const notes = await Note.find({user: req.user.id});
        res.json(notes)
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Interanl Server Error");
    }
})

//ROUTE 2: Add a new Note using: POST "/api/notes/addnotes". login required
router.post('/addnotes', fetchuser,[
    body('title','Enter the title').isLength({ min: 3 }),
    body('description', 'Description must be atleast 5 characters').isLength({ min: 5 }),
], async (req,res)=>{
    try {
        const {title, description, tag} = req.body;
        //If there are errors, return Bad request and the errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() });
        }
    
        const note = new Note({
            title, description, tag, user: req.user.id
        })
        
        const savedNote = await note.save();
        res.json(savedNote)
    
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Interanl Server Error");
    }

})

//ROUTE 3: Update an existing Note using: PUT "/api/notes/updatenotes". login required
router.put('/updatenotes/:id', fetchuser, async (req,res)=>{
    const {title, description, tag} = req.body;
    //Create a newNote
    const newNote = {};
    if(title){
        newNote.title = title;
    }
    if(description){
        newNote.description = description;
    }
    if(tag){
        newNote.tag = tag;
    }

    // Find the note to be updated and update it


})

module.exports = router;