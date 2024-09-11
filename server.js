import express from 'express'
import mongoose from 'mongoose'
import nodemailer from 'nodemailer'
import bcrypt from'bcryptjs'
import dotenv from 'dotenv'
import crypto from 'crypto'
import cors from 'cors'

dotenv.config();
// initiating exoress
const  app = express();
// middleware for JSON parse
app.use(express.json()); 

//Connect to  mongoDB
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("DB connected successfully"))
.catch((error) => console.log(error));

//Creating schema for updating password.
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetToken: String,
    resetTokenExpiry: Date
});

const User = mongoose.model('User', UserSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Generate a random token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).send('User not found');

    const token = generateToken();
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry
    await user.save();

    const resetUrl = `https://passwordrestft.netlify.app/reset-password/${token}`;

    await transporter.sendMail({
        to: email,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: ${resetUrl}`
    });

    res.status(200).send('Password reset email sent');
});

// Reset Password Route
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) return res.status(400).send('Invalid or expired token');

    user.password = await bcrypt.hash(password, 10);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.status(200).send('Password successfully reset');
});

app.listen(process.env.PORT || 5000, () => console.log(`Server running on port ${process.env.PORT || 5000}`));