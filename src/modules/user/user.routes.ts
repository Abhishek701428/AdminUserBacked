import { Router } from 'express';
import { registerUser, verifyOTP, loginAdmin, loginUser } from '../user/user.controller';

const router = Router();

router.post('/register', registerUser);
router.post('/verify-otp', verifyOTP);
router.post('/login', loginAdmin);
router.post('/login/user', loginUser);

export default router;
