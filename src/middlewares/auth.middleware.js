import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    // ✅ 1. Grab token from cookie or header safely
    const tokenFromCookie = req.cookies?.accessToken; // make sure you use cookie-parser middleware
    const authHeader = req.header("Authorization");

    const token =
      tokenFromCookie ||
      (authHeader?.startsWith("Bearer ")
        ? authHeader.replace("Bearer ", "")
        : null);

    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    // ✅ 2. Verify and decode token
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // ✅ 3. Find user
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    if (!user) {
      throw new ApiError(401, "Invalid Access Token");
    }

    // ✅ 4. Attach user to request
    req.user = user;

    next();
  } catch (error) {
    console.error("JWT verification failed:", error);
    throw new ApiError(401, error?.message || "Invalid Access Token");
  }
});
