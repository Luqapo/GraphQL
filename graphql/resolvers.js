const userResolver = require('./resolvers/user');
const postsResolver = require('./resolvers/posts');

module.exports = {
    ...userResolver,
    ...postsResolver
}