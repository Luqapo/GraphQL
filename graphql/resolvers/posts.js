const validator = require('validator');

const clearImage = require('../../middleware/clearImage');

const User = require('../../models/user');
const Post = require('../../models/post');

const transformPost = post => {
    return { 
        ...post._doc, 
        _id: post._id.toString(), 
        createdAt: post.createdAt.toISOString(), 
        updatedAt: post.updatedAt.toISOString() 
    };
}

module.exports = {
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

        return transformPost(post);
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
            return transformPost(p);
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
        
        return transformPost(post);
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

        return transformPost(post);
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
            message: 'Post deleted.'
        }
    }
};