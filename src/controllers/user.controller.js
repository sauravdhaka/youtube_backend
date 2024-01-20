import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudnary.js";
import { ApiResponse } from "../utils/ApiResponse.js";



const generateAccessTokenAndRefereshToken = async (userId)=>{
   try {
      const user = await User.findById(userId)
      const accessToken = user.generateAccessToken()
      const refereshToken = user.generateRefreshToken()
      user.refreshToken = refereshToken
      await user.save({validateBeforeSave:false})
      return {accessToken,refereshToken}
   } catch (error) {
      throw new ApiError(500,"Something went worng while generating referesh token")
   }
}


const registerUser = asyncHandler(async (req, res) => {
  // get user details from fronted
  // validation
  // if user is already exists
  // check for images, check for avatar
  // upload them to cloudinary , avatar
  // craete user object - create entry in db
  // remove password and refresh token field from response
  // check for user creation
  // return response

  const { fullName, email, username, password } = req.body;
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  //    const coverImageLocalPath = req.files?.coverImage[0]?.path

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while regestring user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered Successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  // email and password
  // username or email exists or not
  // find the user
  // validated password
  // access and refresh token
  // send cookies

  const { email, password, username } = req.body;
  if (!username && !email) {
    throw new ApiError(400, "username or email is required!!!");
  }

  const user = await User.findOne({ $or: [{ email }, { username }] });

  if(!user){
   throw new ApiError(404,"User does not exist")
  }

  const isPasswordValid = await user.isPasswordCorrect(password)

  if(!isPasswordValid){
   throw new ApiError(401,"Invalid user credentials")
  }
  
  const {accessToken,refereshToken} = await generateAccessTokenAndRefereshToken(user._id)

  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  const options = {
   httpOnly : true,
   secure : true
  }

  return res.status(200)
  .cookie("accessToken",accessToken,options)
  .cookie("refreshToken",refereshToken,options)
  .json(
   new ApiResponse(200,{
      user : loggedInUser,accessToken,refereshToken
   },"User logged In Successfully")
  )

});


const loggoutUser = asyncHandler(async (req,res)=>{
   await User.findByIdAndUpdate(
      req.user._id,
      {
         $set : {
            refereshToken : undefined
         }
      },{
         new : true
      }
   )
   const options = {
      httpOnly : true,
      secure : true
     }
     return res.status(200)
     .clearCookie("accessToken",options)
     .clearCookie("refreshToken",options)
     .json(new ApiResponse(200,{},"User Logged Out"))
})

export { registerUser, loginUser , loggoutUser };
