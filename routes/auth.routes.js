const {Router} = require('express')
const router = Router()
const User = require("../models/User")
const bcrypt = require("bcrypt")
const config = require("config")
const jwt = require('jsonwebtoken')
const { check, validationResult } = require('express-validator')

router.post(
    "/register",
    [
        check("email","sxal emmail").isEmail(),
        check("password","minimum characters 6 symbol")
    ],
    async (req,res)=>{

    try{
        const errors = validationResult(req)
        if(!errors.isEmpty()){
            return res.status(400).json({errors : errors.array(),message: "invalid data"})
        }
        const {email, password} = req.body

        const condidate = await User.findOne({email})
        if(condidate){
           return  res.status(400).json({message: "user have email"})
        }
        const hashedPassword = await bcrypt.hash(password,12)

        const user = new User({email,password:hashedPassword})

        await user.save()

        res.status(201).json({message: "user created"})
    } catch(e){
        res.status(500).json({message: "try agen"})
    }
})
router.post(
    "/login",
    [
        check("email","enter correct email").normalizeEmail().isEmail(),
        check("password","enter password").exists()
    ],
    async (req,res)=>{
        try{
            const errors = validationResult(req)

            if(!errors.isEmpty()){
                return res.status(400).json({errors : errors.array(),message: "invalid data"})
            }

            const {email,password} = req.body

            const user = await User.findOne({email})

            if(!user){
                return res.status(400).json({message: "user did not found"})
            }

            const isMatch = await bcrypt.compare(password,user.password)

            if(!isMatch){
                return res.status(400).json({message: "password do not correct"})
            }

            const token = jwt.sign(
                {userId : user.id},
                config.get("jwtSecret"),
                {expiresIn:"1h"}
            )

             res.json({token,userId:user.id})
        }catch(e){
            res.status(500).json({message: "try agen"})
        }
})

module.exports = router