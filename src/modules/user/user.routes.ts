import { Router } from 'express';
import { registerUser, verifyOTP, loginAdmin } from '../user/user.controller';

const router = Router();

router.post('/register', registerUser);
router.post('/verify-otp', verifyOTP);
router.post('/login', loginAdmin);

export default router;
