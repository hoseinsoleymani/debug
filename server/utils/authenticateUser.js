import jwt from "jsonwebtoken";

import validateInput from "./validateInput";

const SingleSignOnKey = "SingleSignOnKey";

export default async function authenticateUser(request, queryData) {
  const { ssoToken } = queryData;
  try {
    const userData = await jwt.verify(ssoToken, SingleSignOnKey);
    delete queryData.ssoToken;

    if (!userData.id) {
      throw new Error("Missing id in user data");
    } else if (userData.email && !validateInput.email(userData.email)) {
      throw new Error("Invalid email in user data");
    } else if (!userData.name) {
      throw new Error("Missing name in user data");
    }

    return userData;
  } catch (error) {
    throw new Error(error)
  }
}

module.exports = authenticateUser;
