import express from 'express';//The core framework for building the Node.js server.
import cors from 'cors';
import helmet from 'helmet';// Secures HTTP headers
import morgan from 'morgan';//(for depugging and testing) Morgan is like a flight recorder for your API—it logs who called what and how long it took.
import authRoutes from './routes/authRoutes.js';
import { notFound, errorHandler } from './middleware/error.js';//Custom middleware for handling 404s and errors.
import './config/db.js';//this for ROW // Starts the app only if DB is ready
// import './config/dbS.js';this is for OMR

//cookies and seation 
import session from 'express-session';
import cookieParser from 'cookie-parser';
const app = express();

// ================= Security & Parsing Middleware =====================
app.use(helmet());
app.use(cors({//function
  origin: process.env.CORS_ORIGIN || '*',// property (key) : value
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],// Content-Type & Authorization (http headers)
  credentials: true,
}));
//the sec  every thing from cors 
//morgan if the logs in production or deve
//node env morgan  work for development or producation should check the env 
//attriput from dev to production if the morgain is combained or dev 
// Logging
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
//we don't use bodyparser so in the express make the pars for this 

// Body parser
app.use(express.json());//1 Parses JSON data sent in requests (e.g., POST/PUT with Content-Type: application/json).//2 Converts the JSON body into a JavaScript object (accessible via req.body).
app.use(express.urlencoded({ extended: true }));

//=========================

//for session and cookies and put the last middleware we use 

app.use(cookieParser());
app.use(session({
  secret:process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:false,
  cookie:{
    secure:process.env.NODE_ENV === 'production',
    httpOnly:true,
    maxAge: 24* 60 * 60 *1000, //for one day just (more than one day just mult*4 =>for four days )
    sameSite:'strict',

  },
}));

// ================= Routes =====================
app.use('/api/auth', authRoutes);//if authRoutes.js has:  router.get('/login', loginController); ===> The full path becomes: ===> http://localhost:5000/api/auth/login

// Health check
app.get('/health', (req, res) => res.json({ status: 'OK' }));// health check route

// Error handling
app.use(notFound);
// Purpose
// Catches requests to undefined routes (no matching route found)

// Returns a standardized 404 Not Found response

// Prevents Express from sending its default HTML 404 page
app.use(errorHandler);
// Purpose
// Centralized handling of all uncaught errors

// Prevents sensitive error details from leaking to clients

// Standardizes error responses across the app



export default app;//Share this Express app with other files.( so i can import it in server.js )

//Q: We use app.use(notFound) and app.use(errorHandler) instead of direct imports because:
//Answer: They must run after all routes (to catch 404s) and before the server ends
// They require (req, res, next) parameters that only app.use() provides
// The framework expects error handlers to be registered this way
// Short version:
//app.use() puts them in the right place with the right context. Direct imports wouldn't work properly.