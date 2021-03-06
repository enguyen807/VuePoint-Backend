const { buildSchema } = require('graphql')

module.exports = buildSchema(`
  type User {
    _id: ID!
    name: String!
    email: String!
    country: String!
    password: String!
    isVerified: Boolean!
    isAdmin: Boolean!
  }

  type AuthData {
    token: String!
    userId: String!
    isVerified: Boolean!
    isAdmin: Boolean!
  }  

  input UserInputData {
    email: String!
    name: String!
    password: String!
    country: String!
  }

  type RootQuery {
      login(email: String!, password: String!): AuthData!
      user: User!
  }  

  type RootMutation {
    createUser(userInput: UserInputData): User!
    verifyEmail(email: String!): User!
  }

  schema {
      query: RootQuery
      mutation: RootMutation
  }
`)