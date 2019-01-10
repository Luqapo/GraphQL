const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const Post = require('../models/post');

module.exports = {
    createUser: async function({ userInput }, req) {
        //const email = args.userInput.email;
        const errors = [];
        if(!validator.isEmail(userInput.email)){
            errors.push({message: 'E-Mail is invalid.'})
        }
        if(
            validator.isEmpty(userInput.password) || 
            !validator.isLength(userInput.password, {min: 5})
        ){
            errors.push({message: 'Password to short.'})
        }
        if(errors.length > 0){
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const existingUser = await User.findOne({email: userInput.email});
        if(existingUser) {
            const error = new Error('User exist');
            throw error;
        }
        const hashedPw = await bcrypt.hash(userInput.password, 12);
        const user = await User.create({
            email: userInput.email,
            name: userInput.name,
            password: hashedPw
        });
        
        return { ...user._doc, _id: user._id.toString() };
    },
    login: async function({ email, password }) {
        const user = await User.findOne({email: email});
        if(!user){
            const error = new Error('User not found.');
            error.code = 404;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if(!isEqual){
            const error = new Error('Password is incorrect.');
            error.code = 401;
            throw error;
        }
        const token = jwt.sign(
            {
                email: email,
                userId: user._id.toString()
            },
            'graphqlsecret',
            { expiresIn: '1h' }
        );
        return { token: token, userId: user._id.toString() };
    },
    createPost: async ({ postInput }, req) => {
        console.log(postInput);
        const errors = [];
        if(!validator.isEmpty(userInput.title)){
            errors.push({message: 'Title is invalid.'})
        }
        if(
            validator.isEmpty(userInput.content) || 
            !validator.isLength(userInput.content, {min: 5})
        ){
            errors.push({message: 'Content to short.'})
        }
        if(!validator.isEmpty(userInput.imageUrl)){
            errors.push({message: 'ImageUrl should not be empty.'})
        }
        if(errors.length > 0){
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const post = await Post.create({
            title: postInput.title,
            content: postInput.content,
            imageUrl: postInput.imageUrl
        })

        return { 
            ...post._doc, 
            _id: post._id.toString(), 
            createdAt: post.createdAt.toISOString(), 
            updatedAt: post.updatedAt.toISOString() };
    }
};