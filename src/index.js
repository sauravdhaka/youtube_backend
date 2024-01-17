// require('dotenv').config({path:'./env'})
import dotenv from "dotenv"
import connectDB from "./db/index.js";

dotenv.config({path:'./env'})

connectDB()

















/*
const app = express();
(async()=>{
    try {
        await mongoose.connect(`${process.env.MONOGODB_URI}/${DB_NAME}`)
        app.on("errror",(error)=>{
            console.log("ERROR ",error);
            throw error
        })

        app.listen(process.env.PORT,()=>{
            console.log(`App is runing on port ${process.env.PORT}`)
        })
    } catch (error) {
        console.error("ERROR ",error)
        throw error
    }
})

*/

