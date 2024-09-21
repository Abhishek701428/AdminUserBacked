import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  role: string;
  isVerified: boolean;
  otp: string;
  otpExpiry: Date;
}

const UserSchema: Schema = new Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'customer'], required: true },
  isVerified: { type: Boolean, default: false },
  otp: { type: String, required: true },
  otpExpiry: { type: Date, required: true },
});

export default mongoose.model<IUser>('User', UserSchema);
