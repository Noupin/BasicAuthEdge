import cf from "cloudfront";

const kvsId = "3c7a330f-02a4-4917-af31-e18fae2a2905";
const kvsHandle = cf.kvs(kvsId);

const generateUnauthorizedResponse = () => {
  return {
    statusCode: 401,
    statusDescription: "Unauthorized",
    headers: {
      "www-authenticate": { value: 'Basic realm="Secure Area"' },
      "content-type": { value: "text/html" },
    },
    body: "Unauthorized: Access is denied.",
  };
};

const isValidPart = (part) => {
  const partRegex = /^[a-zA-Z0-9\-_.@]+$/;
  return partRegex.test(part);
};

const timingSafeEqual = (a, b) => {
  const length = Math.max(a.length, b.length);
  let result = 0;
  for (let i = 0; i < length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
};

async function handler(event) {
  const request = event.request;
  const headers = request.headers;

  if (!headers.authorization || headers.authorization.length === 0) {
    return generateUnauthorizedResponse();
  }

  const authString = headers.authorization.value.split(" ")[1];
  if (!authString) {
    return generateUnauthorizedResponse();
  }

  let decodedAuth;
  try {
    decodedAuth = atob(authString).split(":");
  } catch (error) {
    return generateUnauthorizedResponse();
  }

  if (decodedAuth.length !== 2) {
    return generateUnauthorizedResponse();
  }

  const username = decodedAuth[0];
  const password = decodedAuth[1];

  // Extract environment and app from the hostname
  const hostnameParts = headers.host.value.split(".");
  const environment = hostnameParts[0];
  const app = hostnameParts[1];

  if (
    !isValidPart(environment) ||
    !isValidPart(app) ||
    !isValidPart(username)
  ) {
    return generateUnauthorizedResponse();
  }

  const key = `${environment}/${app}/${username}`;
  try {
    const passwordToCheckAgainst = await kvsHandle.get(key, {
      format: "string",
    });

    if (
      !passwordToCheckAgainst ||
      !timingSafeEqual(password, passwordToCheckAgainst)
    ) {
      return generateUnauthorizedResponse();
    }

    // Authentication successful, return the original request
    return request;
  } catch (error) {
    return generateUnauthorizedResponse();
  }
}

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
