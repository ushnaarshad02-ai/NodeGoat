"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const consolidate = require("consolidate");
const path = require("path");
const helmet = require("helmet");

// --- WEEK 4 IMPORTS: API HARDENING ---
const rateLimit = require("express-rate-limit");
const cors = require("cors");

// --- WEEK 3 START: FIXED WINSTON IMPORT ---
const winston = require("winston");

// Use a conditional check to support both winston 2.x and 3.x
const logger = (winston.createLogger) 
    ? winston.createLogger({
        transports: [
            new winston.transports.Console(),
            new winston.transports.File({ filename: "security.log" })
        ]
    })
    : new winston.Logger({
        transports: [
            new winston.transports.Console(),
            new winston.transports.File({ filename: "security.log" })
        ]
    });
// --- WEEK 3 END ---

const { MongoClient } = require("mongodb");
const routes = require("./app/routes");
const {
    port,
    db: dbUrl,
    cookieSecret
} = require("./config/config");

const app = express();

// --- WEEK 4: API SECURITY HARDENING CONFIGURATIONS ---

// 1. Define the Rate Limiting rule (Max 100 requests per 15 minutes)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes window
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        status: 429,
        error: "Too many requests from this IP, please try again after 15 minutes."
    },
    standardHeaders: true, 
    legacyHeaders: false, 
});

// 2. Configure CORS to restrict unauthorized cross-origin access (UPDATED STRICT POLICIES)
const corsOptions = {
    origin: ['http://localhost:4000', 'http://127.0.0.1:4000'], // Allow only your specific trusted client domains
    methods: ['GET', 'POST', 'PUT', 'DELETE'],                  // Restrict allowed HTTP verbs
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'], // Limit exposed request headers (including our API Key)
    credentials: true,                                          // Allow session cookies or auth tokens across origins
    optionsSuccessStatus: 200
};

// 3. Define custom API Key Validation Rule
const VALID_API_KEY = "nodegoat_secure_api_key_2026"; 

const validateApiKey = (req, res, next) => {
    // Intercept requests targeting backend API endpoints
    if (req.path.startsWith('/api/')) {
        const apiKey = req.headers['x-api-key'];

        if (!apiKey || apiKey !== VALID_API_KEY) {
            logger.warn(`Unauthorized API access attempt blocked from IP: ${req.ip} on route: ${req.path}`);
            return res.status(401).json({
                status: 401,
                error: "Unauthorized: Invalid or missing API Key (X-API-Key header required)."
            });
        }
    }
    next(); 
};


// --- GLOBAL SECURITY MIDDLEWARES ---

// 1. SECURITY: Initialize Helmet with custom CSP and HSTS rules (Task 3)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Allows inline scripts used by NodeGoat while stopping malicious injection
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
        },
    },
    hsts: {
        maxAge: 31536000, // Enforces Strict-Transport-Security (HTTPS) for 1 year
        includeSubDomains: true,
        preload: true
    }
})); 

// 2. Apply Rate Limiting globally across routes (Task 2)
app.use(apiLimiter);

// 3. Apply CORS cross-origin protections (Task 2)
app.use(cors(corsOptions));

// 4. Enforce custom API key checks for data endpoints (Task 2)
app.use(validateApiKey);


app.set("views", path.join(__dirname, "app/views"));
app.engine("html", consolidate.swig);
app.set("view engine", "html");

app.use(express.static(path.join(__dirname, "app/assets")));
app.use(favicon(path.join(__dirname, "app/assets/favicon.ico")));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: cookieSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: false 
    }
}));

// 2. DATABASE CONNECTION & SERVER START
MongoClient.connect(dbUrl, { useUnifiedTopology: true }, (err, client) => {
    if (err) {
        logger.error("Database connection failed: " + err);
        process.exit(1);
    }

    console.log("Connected successfully to MongoDB");
    const db = client.db();

    // 3. REGISTER ROUTES
    routes(app, db);

    app.listen(port, () => {
        logger.info("Application started");
        console.log(`Server started on port ${port}`);
    });
});
