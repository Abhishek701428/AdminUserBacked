import express from 'express';
import { Request, Response } from 'express';
import bodyParser from 'body-parser';
import cors from 'cors'
import path from 'path';
import dotenv from 'dotenv';
import http from 'http';
dotenv.config();
import connectToMongo from './database/db';
import router from './modules/user/user.routes';

const app = express();
connectToMongo();
const server = http.createServer(app);


app.get('/', (req: Request, res: Response) => {
    res.send("Hi, I am TypeScript! Any problem . Noo!!");
});
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors({
    'allowedHeaders': ['Authorization', 'Content-Type']
}))
app.use(cors())

app.use('/api/auth',router)

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

