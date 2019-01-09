const { buildSchema } = require('graphql');

module.exports = buildSchema(`
    type TestData {
        text: String!
        vievs: Int!

    }

    type RootQuery {
        hello: TestData!
    }

    schema {
        query: RootQuery
    }
`);