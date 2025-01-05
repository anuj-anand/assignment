import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

// user registration

export const  register = async(req,res)=>{
    try {
        const{
            firstName,
            lastName,
            email,
            password,
            picturePath,
            friends,
            location,
            occupation,
          } = req.body;

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password,salt);

        const newUser = new User({
            firstName,
            lastName,
            email,
            password:passwordHash,
            picturePath,
            friends,
            location,
            occupation,
            viewedProfile:Math.floor(Math.random()*10000),
            impressions: Math.floor(Math.random()*10000)
        });
        const savedUser = await newUser.save();
        res.status(201).json(savedUser)
    } catch (error) {
        res.status(500).json({error:error.message});
    }
}


export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "User does not exist." });
    }

    // Compare the entered password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials." });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    // Exclude the password field from the user object
    const { password: _, ...userWithoutPassword } = user.toObject();

    res.status(200).json({ token, user: userWithoutPassword });
  } catch (err) {
    console.error("Login error:", err.message || err);
    res.status(500).json({ error: "Something went wrong. Please try again later." });
  }
};

// login
// export const login = async (req, res) => {
//     try {
//       const { email, password } = req.body;
//       const user = await User.findOne({ email: email });
//       if (!user) return res.status(400).json({ msg: "User does not exist. " });
  
//       const isMatch = await bcrypt.compare(password, user.password);
//       if (!isMatch) return res.status(400).json({ msg: "Invalid credentials. " });
  
//       const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
//       delete user.password;
//       res.status(200).json({ token, user });
//     } catch (err) {
//       res.status(500).json({ error: err.message });
//     }
//   };