import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../user/user.model';
import { generateOTP } from '../user/generateotp';

// Generate JWT Token for authentication
const generateToken = (userId: string, secret: string) => {
  return jwt.sign({ id: userId }, secret, { expiresIn: '1h' }); 
};

// Registration with OTP generation
export const registerUser = async (req: Request, res: Response) => {
  const { firstName, lastName, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role,
      otp,
      otpExpiry: new Date(Date.now() + 10 * 60 * 1000), 
      isVerified: false,
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully. OTP sent.', otp });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error });
  }
};

// OTP Verification
export const verifyOTP = async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.otp === otp && user.otpExpiry! > new Date()) {
      user.isVerified = true;
      user.otp = '';
      user.otpExpiry = null;
      await user.save();

      return res.status(200).json({ message: 'Email verified successfully' });
    }

    return res.status(400).json({ message: 'Invalid or expired OTP' });
  } catch (error) {
    return res.status(500).json({ message: 'Error verifying OTP', error });
  }
};

// Admin Login with JWT Token generation
export const loginAdmin = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'You are not allowed to login from here' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = generateToken(user._id.toString(), process.env.JWT_SECRET!);
    return res.status(200).json({ message: 'Admin login successful', token });
  } catch (error) {
    return res.status(500).json({ message: 'Error logging in', error });
  }
};
