const AWS = require("aws-sdk");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();

exports.handler = async (event) => {
  let response;

  try {
    let body;

    if (typeof event.body === "string") {
      try {
        body = JSON.parse(event.body);
      } catch (error) {
        return {
          statusCode: 400,
          body: JSON.stringify({ message: "Invalid JSON format" }),
        };
      }
    } else {
      body = event.body;
    }

    const { taxpayerId, name, email } = body;

    let cognitoUser = await getUser(taxpayerId);

    if (!cognitoUser) {
      // If no user found, create a new one
      cognitoUser = await createUser(taxpayerId, name, email);
      await confirmUser(taxpayerId);
    }

    const result = await authenticateUser(cognitoUser);

    response = {
      statusCode: 200,
      body: JSON.stringify({
        accessToken: result.getAccessToken().getJwtToken(),
        idToken: result.getIdToken().getJwtToken(),
        refreshToken: result.getRefreshToken().getToken(),
      }),
    };
  } catch (error) {
    console.error(error);
    response = {
      statusCode: error.statusCode || 500,
      body: JSON.stringify({
        error: error.message || "Internal Server Error",
      }),
    };
  } finally {
    console.log("response: " + response);

    return response;
  }
};

async function getUser(taxpayerId) {
  try {
    const params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: taxpayerId,
    };

    const data = await cognitoIdentityServiceProvider
      .adminGetUser(params)
      .promise();

    // Create a CognitoUser instance based on the returned Username
    const userData = {
      Username: data.Username,
      Pool: new AmazonCognitoIdentity.CognitoUserPool({
        UserPoolId: process.env.USER_POOL_ID,
        ClientId: process.env.CLIENT_ID,
      }),
    };

    return new AmazonCognitoIdentity.CognitoUser(userData);
  } catch (error) {
    if (error.code === "UserNotFoundException") {
      return null; // Return null if user does not exist
    } else {
      console.error("Error getting user by username:", error);
      throw error; // Re-throw other errors
    }
  }
}

async function createUser(taxpayerId, name, email) {
  try {
    const attributeList = [
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "name",
        Value: name,
      }),
      new AmazonCognitoIdentity.CognitoUserAttribute({
        Name: "email",
        Value: email,
      }),
    ];

    const signUpParams = {
      ClientId: process.env.CLIENT_ID,
      Username: taxpayerId, // use the taxpayerId as both username and password
      Password: taxpayerId,
      UserAttributes: attributeList,
    };

    await cognitoIdentityServiceProvider.signUp(signUpParams).promise();

    const userData = {
      Username: taxpayerId,
      Pool: new AmazonCognitoIdentity.CognitoUserPool({
        UserPoolId: process.env.USER_POOL_ID,
        ClientId: process.env.CLIENT_ID,
      }),
    };

    return new AmazonCognitoIdentity.CognitoUser(userData);
  } catch (error) {
    console.error("Error creating user:", error);
    throw error;
  }
}

async function authenticateUser(user) {
  try {
    return await new Promise((resolve, reject) => {
      user.authenticateUser(
        new AmazonCognitoIdentity.AuthenticationDetails({
          Username: user.getUsername(),
          Password: user.getUsername(),
        }),
        {
          onSuccess: (result) => resolve(result),
          onFailure: (err) => reject(err),
        }
      );
    });
  } catch (error) {
    console.error("Authentication failed:", error);
    throw error;
  }
}

async function confirmUser(username) {
  const params = {
    UserPoolId: process.env.USER_POOL_ID,
    Username: username,
  };

  try {
    await cognitoIdentityServiceProvider.adminConfirmSignUp(params).promise();
    console.log(`User ${username} has been confirmed successfully.`);
  } catch (error) {
    console.error("Error confirming user:", error);
    throw error;
  }
}
