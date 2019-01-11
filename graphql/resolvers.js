const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const clearImage = require('../middleware/clearImage');

const User = require('../models/user');
const Post = require('../models/post');

module.exports = {
    createUser: async ({ userInput }, req) => {
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
    login: async ({ email, password }) => {
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
        if(!req.isAuth){
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const errors = [];
        if(validator.isEmpty(postInput.title)){
            errors.push({message: 'Title is invalid.'})
        }
        if(
            validator.isEmpty(postInput.content) || 
            !validator.isLength(postInput.content, {min: 5})
        ){
            errors.push({message: 'Content to short.'})
        }
        if(validator.isEmpty(postInput.imageUrl)){
            errors.push({message: 'ImageUrl should not be empty.'})
        }
        if(errors.length > 0){
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const user = await User.findById(req.userId);
        if(!user){
            const error = new Error('Invalid user!');
            error.code = 401;
            throw error;
        }
        const post = await Post.create({
            title: postInput.title,
            content: postInput.content,
            imageUrl: postInput.imageUrl,
            creator: user
        })
        user.posts.push(post);
        await user.save();

        return { 
            ...post._doc, 
            _id: post._id.toString(), 
            createdAt: post.createdAt.toISOString(), 
            updatedAt: post.updatedAt.toISOString() };
    },
    loadPosts: async ({ page }, req) => {
        if(!req.isAuth){
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        if(!page){
            page = 1;
        }
        const perPage = 2;
        const posts = await Post.find()
            .sort({ createdAt: -1 })
            .skip((page -1) * perPage)
            .limit(perPage)
            .populate('creator');
        const totalPosts = await Post.find().countDocuments();

        return { posts: posts.map(p => {
            return {
                ...p._doc,
                _id: p._id.toString(),
                createdAt: p.createdAt.toISOString(),
                updatedAt: p.updatedAt.toISOString()
            };
        }), 
        totalPosts: totalPosts };
    },
    loadPost: async ({ postId }, req) => {
        if(!req.isAuth){
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const post = await Post.findById(postId).populate('creator');
        if(!post){
            const error = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        
        return { 
            ...post._doc, 
            _id: post._id.toString(), 
            createdAt: post.createdAt.toISOString(), 
            updatedAt: post.updatedAt.toISOString() 
        }
    },
    editPost: async ({postId, postInput}, req) => {
        if(!req.isAuth){
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const errors = [];
        if(validator.isEmpty(postInput.title)){
            errors.push({message: 'Title is invalid.'})
        }
        if(
            validator.isEmpty(postInput.content) || 
            !validator.isLength(postInput.content, {min: 5})
        ){
            errors.push({message: 'Content to short.'})
        }
        if(errors.length > 0){
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const post = await Post.findById(postId).populate('creator');
        if(!post){
            const error = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        if(post.creator._id.toString() !== req.userId.toString()){
            const error = new Error('Not authorized to edit that post!');
            error.code = 403;
            throw error;
        }
        post.title = postInput.title;
        post.content = postInput.content;
        if(postInput.imageUrl !== 'undefined'){
            post.imageUrl = postInput.imageUrl;
        }
        await post.save();

        return { 
            ...post._doc, 
            _id: post._id.toString(), 
            createdAt: post.createdAt.toISOString(), 
            updatedAt: post.updatedAt.toISOString() 
        };
    },
    deletePost: async ({ postId }, req) => {
        if(!req.isAuth){
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const deletedPost = await Post.findByIdAndDelete(postId);
        if(!deletedPost){
            const error = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        if(deletedPost.creator.toString() !== req.userId.toString()){
            const error = new Error('Not authorized to edit that post!');
            error.code = 403;
            throw error;
        }
        clearImage(deletedPost.imageUrl);
        const user = await User.findById(req.userId);
        user.posts.pull(postId);
        await user.save();

        return {
            message: 'Post deleted.',
            post: {
                ...deletedPost._doc, 
            _id: deletedPost._id.toString(), 
            createdAt: deletedPost.createdAt.toISOString(), 
            updatedAt: deletedPost.updatedAt.toISOString() 
            }
        }
    }
};