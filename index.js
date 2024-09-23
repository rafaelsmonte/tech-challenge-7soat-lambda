const AWS = require("aws-sdk");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js"); // Ensure this is included in your Lambda deployment package

const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();

exports.handler = async (event) => {
  const poolData = {
    UserPoolId: process.env.USER_POOL_ID,
    ClientId: process.env.CLIENT_ID,
  };

  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  try {
    // Ensure the payload is correctly parsed
    let body;

    // Check if the body needs parsing (when called via API Gateway)
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

    // Extract parameters
    const { taxpayerId, name, email } = body;

    // First, try to find the user
    let cognitoUser = await getUserByTaxpayerId(taxpayerId);

    if (!cognitoUser) {
      // If no user found, create a new one
      cognitoUser = await createUser(taxpayerId, name, email);

      // Confirm user sign up (adminConfirmSignUp)
      await confirmUser(taxpayerId);
    }

    // Proceed with login
    const result = await authenticateUser(cognitoUser);

    return {
      accessToken: result.getAccessToken().getJwtToken(),
      idToken: result.getIdToken().getJwtToken(),
      refreshToken: result.getRefreshToken().getToken(),
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: error.statusCode || 500,
      error: error.message || "Internal Server Error",
    };
  }
};

// Function to get user by taxpayerId (username)
async function getUserByTaxpayerId(taxpayerId) {
  try {
    const params = {
      UserPoolId: process.env.USER_POOL_ID, // Cognito User Pool ID
      Username: taxpayerId, // Using taxpayerId as the username
    };

    // Use AdminGetUser to retrieve user by username (taxpayerId)
    const data = await cognitoidentityserviceprovider
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

// Function to create a new user
async function createUser(username, name, email) {
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
      Username: username,
      Password: process.env.PASSWORD,
      UserAttributes: attributeList,
    };

    await cognitoidentityserviceprovider.signUp(signUpParams).promise();

    const userData = {
      Username: username,
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

// Function to authenticate a user
async function authenticateUser(user) {
  try {
    return await new Promise((resolve, reject) => {
      user.authenticateUser(
        new AmazonCognitoIdentity.AuthenticationDetails({
          Username: user.getUsername(),
          Password: process.env.PASSWORD,
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

// async function authenticateUser(user) {
//   try {
//     const params = {
//       AuthFlow: "ADMIN_NO_SRP_AUTH",
//       UserPoolId: process.env.USER_POOL_ID,
//       ClientId: process.env.CLIENT_ID,
//       AuthParameters: {
//         USERNAME: user.getUsername(),
//         // Use a fixed password, or leave this empty if your policy allows it.
//         // This is not a recommended security practice, but it bypasses the password need.
//         PASSWORD: "NO_PASSWORD", // Note: May need to set to a known fixed value depending on your settings.
//       },
//     };

//     return await cognitoidentityserviceprovider
//       .adminInitiateAuth(params)
//       .promise();
//   } catch (error) {
//     console.error("Authentication failed:", error);
//     throw error;
//   }
// }

// Function to confirm a user (adminConfirmSignUp)
async function confirmUser(username) {
  const params = {
    UserPoolId: process.env.USER_POOL_ID,
    Username: username,
  };

  try {
    await cognitoidentityserviceprovider.adminConfirmSignUp(params).promise();
    console.log(`User ${username} has been confirmed successfully.`);
  } catch (error) {
    console.error("Error confirming user:", error);
    throw error;
  }
}
