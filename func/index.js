import {
  SSMClient,
  GetParameterCommand,
  GetParametersByPathCommand,
} from "@aws-sdk/client-ssm";
import crypto from "crypto";

const generateUnauthorizedResponse = () => {
  return {
    status: "401", // Unauthorized
    statusDescription: "Unauthorized",
    headers: {
      "www-authenticate": [
        { key: "WWW-Authenticate", value: "Basic realm='Secure Area'" },
      ],
      "content-type": [{ key: "Content-Type", value: "text/html" }],
    },
    body: "Unauthorized: Access is denied due to invalid credentials.",
  };
};

function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return crypto.timingSafeEqual(bufA, bufB);
}

function isValidUsername(username) {
  const usernameRegex = /^[a-zA-Z0-9]+$/;
  return usernameRegex.test(username);
}

export const handler = async (event) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  if (!headers.authorization || headers.authorization.length === 0) {
    return generateUnauthorizedResponse();
  }

  const [username, password] = Buffer.from(
    headers.authorization[0].value.split(" ")[1],
    "base64"
  )
    .toString("utf-8")
    .split(":");

  if (!isValidUsername(username)) {
    return generateUnauthorizedResponse();
  }

  const ssm = new SSMClient({ region: "us-east-1" });
  try {
    const getAvailableUsernamesCommand = new GetParametersByPathCommand({
      Path: "/password/loom/frontend/devEnvironment",
      WithDecryption: true,
    });

    const availableUsernamesResponse = await ssm.send(
      getAvailableUsernamesCommand
    );
    const availableUsernames = availableUsernamesResponse.Parameters.map(
      (param) => param.Name.split("/").pop()
    );

    if (!availableUsernames.includes(username)) {
      return generateUnauthorizedResponse();
    }

    const getParameterCommand = new GetParameterCommand({
      Name: `/password/loom/frontend/devEnvironment/${username}`,
      WithDecryption: true,
    });
    const response = await ssm.send(getParameterCommand);

    // Basic Authentication Credentials
    const passwordToCheckAgainst = response.Parameter.Value;

    // Check for Basic Authentication header
    if (!timingSafeEqual(password, passwordToCheckAgainst)) {
      return generateUnauthorizedResponse();
    }
    return request;
  } catch (error) {
    return {
      status: "500",
      statusDescription: "Internal Server Error",
      headers: {
        "content-type": [{ key: "Content-Type", value: "text/html" }],
      },
      body: "Internal Server Error: Please contact the system administrator.",
    };
  }
};

// handler({
//   Records: [
//     {
//       cf: {
//         request: {
//           headers: {
//             authorization: [
//               {
//                 key: "Authorization",
//                 value: "Basic ",
//               },
//             ],
//           },
//         },
//       },
//     },
//   ],
// });
