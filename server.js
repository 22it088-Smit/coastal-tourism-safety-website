import express from "express";
import env from "dotenv";
import path from 'path';
import { fileURLToPath } from 'url';
import axios from "axios";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import Beach from "./models/Beach.js"; // Import Model
import bcrypt from "bcrypt";
import session from "express-session";
import User from "./models/User.js";
import stripe from 'stripe';
import Hotel from "./models/Hotel.js";
import fs from 'fs';
import https from 'https';



// Config
env.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 3443;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
console.log('Static directory:', path.join(__dirname, 'public'));
app.use(bodyParser.urlencoded({ extended: true }))
app.set('view engine', 'ejs');

// Add session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Add authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://mongodb:27017/weather_app', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("✅ Connected to MongoDB");
}).catch((err) => {
    console.log("❌ MongoDB Connection Error: ", err);
});

// Import custom modules
import { weather_owm } from "./modules/weather_owm.mjs";
import tomorrow_weather from "./modules/tomorrow_weather.mjs";
import aqi_test from "./modules/aqi_test.mjs";
import marine from "./modules/marine.mjs";

// Variables
let lat, lon, place;
export let weather_data = {
    city_name: "",
    weather_icon: "",
    aqi: {
        aqi: "",
        category: ""
    },
    temp: "",
    feels_like: "",
    wind_speed: "",
    wind_dir: "",
    visibility: "",
    rain: "",
    humid: "",
    uvi: "",
    weather_desc: "",
    ocean: {
        swell: "",
        wave: "",
        m_hazard: "Low"
    },
    beach_desc: ""
};
let error = "";

// Initialize stripe
const stripeClient = new stripe(process.env.STRIPE_SECRET_KEY, {
    apiVersion: '2023-10-16' // Use the latest API version
});

// Routes
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;
    let errors = []; // Array to hold different error messages

    // --- Validation Checks ---

    // 1. Check if passwords match
    if (password !== confirmPassword) {
        errors.push({ field: 'confirmPassword', message: 'Passwords do not match.' });
    }

    // 2. Check password strength/criteria (Example: Minimum 8 characters)
    if (password.length < 8) {
         errors.push({ field: 'password', message: 'Password must be at least 8 characters long.' });
    }
    // Add more criteria checks here (e.g., uppercase, number, symbol)
    // if (!password.match(/[A-Z]/)) { errors.push({ message: 'Password must contain an uppercase letter.' }); }
    // if (!password.match(/[0-9]/)) { errors.push({ message: 'Password must contain a number.' }); }
    // if (!password.match(/[^A-Za-z0-9]/)) { errors.push({ message: 'Password must contain a special character.' }); }


    // 3. Check if username or email already exists (Only if previous checks passed)
    if (errors.length === 0) {
        try {
            const existingUser = await User.findOne({ $or: [{ email: email }, { username: username }] });

            if (existingUser) {
                if (existingUser.email === email) {
                    errors.push({ field: 'email', message: 'Email already exists. Please use a different email or log in.' });
                }
                if (existingUser.username === username) {
                     errors.push({ field: 'username', message: 'Username is already taken. Please choose another.' });
                }
            }
        } catch (dbError) {
            console.error("Database error during registration check:", dbError);
            errors.push({ field: 'form', message: 'An error occurred during registration. Please try again.' });
        }
    }

    // --- Process Registration or Show Errors ---

    if (errors.length > 0) {
        // If there are errors, re-render the registration page with errors and filled fields (except passwords)
        console.log("Registration errors:", errors);
        res.render('register', {
            errors: errors, // Pass the array of errors
            username: username, // Keep username filled
            email: email      // Keep email filled
        });
    } else {
        // If validation passes, hash password and create user
        try {
            const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds = 10

            const newUser = new User({
                username,
                email,
                password: hashedPassword
            });

            await newUser.save();
            console.log("User registered successfully:", newUser.username);
            // Redirect to login page after successful registration
            // Optional: Add a success message via flash messages or query params
            res.redirect('/login?registered=success');
        } catch (saveError) {
            console.error("Error saving user:", saveError);
            res.render('register', {
                 errors: [{ field: 'form', message: 'Registration failed. Please try again later.' }],
                 username: username,
                 email: email
            });
        }
    }
});

app.get('/login', (req, res) => {
    let successMessage = null;
    if (req.query.registered === 'success') {
        successMessage = "Registration successful! Please log in.";
    }
    res.render('login', { errors: null, identifier: '', successMessage: successMessage }); // Pass empty identifier initially
});

app.post('/login', async (req, res) => {
    const { identifier, password } = req.body; // Changed 'email' to 'identifier'
    let errors = [];

    if (!identifier || !password) {
        errors.push({ field: 'form', message: 'Please enter both username/email and password.' });
        return res.render('login', { errors: errors, identifier: identifier, successMessage: null });
    }

    try {
        // Find user by either email or username (case-insensitive for username check)
        const user = await User.findOne({
            $or: [
                { email: identifier },
                { username: new RegExp('^' + identifier + '$', 'i') } // Case-insensitive username match
            ]
        });

        if (!user) {
            errors.push({ field: 'form', message: 'Invalid credentials. Please check your username/email and password.' });
            return res.render('login', { errors: errors, identifier: identifier, successMessage: null });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            errors.push({ field: 'form', message: 'Invalid credentials. Please check your username/email and password.' });
            return res.render('login', { errors: errors, identifier: identifier, successMessage: null });
        }

        // --- Login Successful ---
        req.session.userId = user._id; // Store user ID in session
        console.log(`User logged in: ${user.username} (ID: ${user._id})`);

        // Regenerate session to prevent fixation attacks
        req.session.regenerate((err) => {
            if (err) {
                console.error("Session regeneration error:", err);
                 errors.push({ field: 'form', message: 'Login failed due to a server error. Please try again.' });
                 return res.render('login', { errors: errors, identifier: identifier, successMessage: null });
            }
            // Store user ID again after regeneration
            req.session.userId = user._id;
            res.redirect('/'); // Redirect to the main page
        });


    } catch (error) {
        console.error("Login error:", error);
        errors.push({ field: 'form', message: 'An error occurred during login. Please try again.' });
        res.render('login', { errors: errors, identifier: identifier, successMessage: null });
    }
});

// 
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});
app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { id: req.session.userId } : null;
    next();
});


app.get('/', requireAuth, (req, res) => {
    res.render('index.ejs', { error: error });
});

// Function to generate beach visit description
function generateBeachVisitDescription(weatherData) {
    let isVisitable = true;
    let reasons = [];
    let recommendations = [];
    let alertLevel = "Safe";
    let alertColor = "green";

    // Check wave height conditions
    const waveHeight = parseFloat(weatherData.ocean.wave);
    if (waveHeight >= 0.0 && waveHeight <= 0.3) {
        reasons.push("Wave conditions are very calm and ideal for swimming");
        alertLevel = "Ideal to Visit";
        alertColor = "#007759";
    } else if (waveHeight > 0.3 && waveHeight <= 0.5) {
        reasons.push("Wave conditions are safe for most swimmers");
        alertLevel = "Safe to Visit";
        alertColor = "green";
    } else if (waveHeight > 0.5 && waveHeight <= 1.2) {
        reasons.push("Moderate wave conditions - exercise caution");
        recommendations.push("Stay within your depth and be aware of changing conditions");
        alertLevel = "Be Cautious";
        alertColor = "yellow";
    } else if (waveHeight > 1.2 && waveHeight <= 2.0) {
        reasons.push("High wave conditions - not recommended for casual swimmers");
        recommendations.push("Only experienced swimmers should enter the water");
        isVisitable = false;
        alertLevel = "Not Recommended";
        alertColor = "orange";
    } else if (waveHeight > 2.0) {
        reasons.push("Dangerous wave conditions");
        recommendations.push("Swimming is not advised");
        isVisitable = false;
        alertLevel = "Dangerous";
        alertColor = "red";
    }

    // Check AQI conditions
    const aqi = parseInt(weatherData.aqi.aqi);
    if (aqi <= 50) {
        reasons.push("Air quality is good");
    } else if (aqi <= 100) {
        reasons.push("Air quality is moderate");
        recommendations.push("Sensitive individuals should limit prolonged outdoor exposure");
    } else if (aqi > 100) {
        reasons.push("Poor air quality conditions");
        recommendations.push("Consider limiting outdoor activities");
        isVisitable = false;
    }

    // Check UV Index
    const uvi = parseFloat(weatherData.uvi);
    if (uvi >= 8) {
        reasons.push("Very high UV levels");
        recommendations.push("Use strong sunscreen, wear protective clothing, and limit sun exposure between 10 AM and 4 PM");
    } else if (uvi >= 6) {
        reasons.push("High UV levels");
        recommendations.push("Use sunscreen and seek shade during peak hours");
    } else if (uvi >= 3) {
        reasons.push("Moderate UV levels");
        recommendations.push("Use sunscreen");
    }

    // Check temperature
    const temp = parseFloat(weatherData.temp);
    if (temp > 35) {
        reasons.push("Very high temperature");
        recommendations.push("Stay hydrated and avoid prolonged sun exposure");
    } else if (temp < 20) {
        reasons.push("Cool temperature for swimming");
        recommendations.push("Water activities may be uncomfortable without proper gear");
    }

    // Check visibility
    const visibility = parseFloat(weatherData.visibility);
    if (visibility < 5) {
        reasons.push("Low visibility conditions");
        recommendations.push("Extra caution required for water activities");
    }

    // Check wind speed
    const windSpeed = parseFloat(weatherData.wind_speed);
    if (windSpeed > 20) {
        reasons.push("Strong winds present");
        recommendations.push("Be cautious of strong currents and high waves");
        isVisitable = false;
    } else if (windSpeed > 10) {
        reasons.push("Moderate wind conditions");
        recommendations.push("Be aware of wind-generated waves and currents");
    }

    // Check rain probability
    const rain = parseFloat(weatherData.rain);
    if (rain > 50) {
        reasons.push("High chance of rain");
        recommendations.push("Check weather updates and bring rain protection");
    }

    // Generate final description
    let description = `Beach Visit Status: ${isVisitable ? 'Recommended' : 'Not Recommended'}\n\n`;
    description += "Conditions:\n- " + reasons.join("\n- ") + "\n\n";
    if (recommendations.length > 0) {
        description += "Recommendations:\n- " + recommendations.join("\n- ");
    }

    return {
        description,
        isVisitable,
        alertLevel,
        alertColor
    };
}

app.post('/find', requireAuth, async (req, res) => {
    place = req.body['place'];

    try {
        const location = await axios.get(`http://api.openweathermap.org/geo/1.0/direct?q=${place}&limit=5&appid=${process.env.OWM_API}`);
        lat = location.data[0].lat;
        lon = location.data[0].lon;
        place = location.data[0].name;
        weather_data.city_name = place;
    } catch (err) {
        console.log("Location Error:", err);
        return res.redirect('/');
    }

    await weather_owm(lat, lon, weather_data);
    await tomorrow_weather(lat, lon, weather_data);
    await aqi_test(lat, lon, weather_data);
    await marine(lat, lon, weather_data);

    if (weather_data.ocean.wave === 'nullm') {
        error = `The given city does not have a beach.`;
        res.redirect("/");
    } else {
        try {
            // Generate beach description
            const beachVisitInfo = generateBeachVisitDescription(weather_data);
            weather_data.beach_desc = beachVisitInfo.description;
            weather_data.isBeachVisitable = beachVisitInfo.isVisitable;
            weather_data.alertLevel = beachVisitInfo.alertLevel;
            weather_data.alertColor = beachVisitInfo.alertColor;

            const newBeach = new Beach({
                ...weather_data,
                lat,
                lon
            });
            await newBeach.save();
            console.log("✅ Weather data saved to MongoDB");
        } catch (err) {
            console.log("❌ Error saving to MongoDB:", err);
        }
        res.render('map.ejs', { 
            weather: weather_data, 
            lat: lat, 
            lon: lon, 
            place: place,
            user: req.session.userId ? { id: req.session.userId } : null
        });
    }
});

// Get hotels near a beach
app.get('/hotels', async (req, res) => {
    try {
        res.render('hotels', { 
            lat: null, 
            lon: null, 
            beach: null,
            error: null,
            user: req.session.userId ? { id: req.session.userId } : null
        });
    } catch (error) {
        console.error(error);
        res.status(500).render('hotels', { 
            error: 'Failed to load hotels',
            user: req.session.userId ? { id: req.session.userId } : null
        });
    }
});

// Get hotels for a specific location
app.get('/hotels/:lat/:lon', async (req, res) => {
    try {
        const { lat, lon } = req.params;
        console.log(`Searching for hotels near lat: ${lat}, lon: ${lon}`);
        
        // We'll use the static data from the frontend
        res.json({ success: true });
    } catch (error) {
        console.error('Error fetching hotels:', error);
        res.status(500).json({ error: 'Failed to fetch hotels', details: error.message });
    }
});

// Get hotel details
app.get('/hotel/:id', async (req, res) => {
    try {
        const hotel = await Hotel.findById(req.id)
            .populate('reviews.user', 'username');
        res.json(hotel);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch hotel details' });
    }
});

// Add review
app.post('/hotel/:id/review', requireAuth, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const hotel = await Hotel.findById(req.params.id);
        
        hotel.reviews.push({
            user: req.session.userId,
            rating,
            comment
        });
        
        await hotel.save();
        res.json(hotel);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add review' });
    }
});

// Book hotel
app.post('/hotel/:id/book', requireAuth, async (req, res) => {
    try {
        const { checkIn, checkOut, roomType, guests } = req.body;
        const hotel = await Hotel.findById(req.params.id);
        
        // Find room and calculate price
        const room = hotel.rooms.find(r => r.type === roomType);
        if (!room || room.available < 1) {
            return res.status(400).json({ error: 'Room not available' });
        }

        const nights = Math.ceil((new Date(checkOut) - new Date(checkIn)) / (1000 * 60 * 60 * 24));
        const totalPrice = room.price * nights;

        // Create Stripe payment intent
        const paymentIntent = await stripeClient.paymentIntents.create({
            amount: totalPrice * 100, // Stripe uses cents
            currency: 'usd'
        });

        // Create booking
        const booking = {
            user: req.session.userId,
            checkIn: new Date(checkIn),
            checkOut: new Date(checkOut),
            roomType,
            guests,
            totalPrice,
            paymentId: paymentIntent.id
        };

        hotel.bookings.push(booking);
        room.available -= 1;
        await hotel.save();

        res.json({
            booking,
            clientSecret: paymentIntent.client_secret
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to book hotel' });
    }
});

// Get hotels near a specific beach
app.get('/hotels/:lat/:lon/:beach', async (req, res) => {
    try {
        const { lat, lon, beach } = req.params;
        res.render('hotels', { 
            lat, 
            lon, 
            beach: decodeURIComponent(beach),
            error: null,
            user: req.session.userId ? { id: req.session.userId } : null
        });
    } catch (error) {
        console.error(error);
        res.status(500).render('hotels', { 
            error: 'Failed to load hotels',
            user: req.session.userId ? { id: req.session.userId } : null
        });
    }
});

// Add this near the top of your server.js, after other middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!', details: err.message });
});

app.get('/test-static', (req, res) => {
    res.send(`
        <html>
            <body>
                <h1>Testing Static Files</h1>
                <img src="/public/images/beach-login-bg.jpg" alt="Beach" style="max-width: 500px;">
            </body>
        </html>
    `);
});

// Add this to check if static files are being served
app.get('/test', (req, res) => {
    res.send(`
        <img src="/images/beach-login-bg.jpg" alt="test" />
    `);
});

// Add this route to test image serving
app.get('/check-image', (req, res) => {
    const imagePath = path.join(__dirname, 'public/images/beach-login-bg.jpg');
    console.log('Checking image path:', imagePath);
    if (fs.existsSync(imagePath)) {
        res.send('Image exists at: ' + imagePath);
    } else {
        res.send('Image not found at: ' + imagePath);
    }
});

// Add this middleware to set user in locals
app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { id: req.session.userId } : null;
    next();
});

// Production vs Development certificate handling
let options;
if (process.env.NODE_ENV === 'production') {
  // In production, use Let's Encrypt or other CA certificates
  options = {
    key: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/fullchain.pem')
  };
} else {
  // In development, use self-signed certificates
  options = {
    key: fs.readFileSync(path.join(__dirname, 'certificates', 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'certificates', 'cert.pem'))
  };
}
// Beach Safety route
app.get('/beach-safety', requireAuth, (req, res) => {
    res.render('safety', { 
        user: req.session.userId ? { id: req.session.userId } : null,
        weather: weather_data
    });
});

// Create HTTPS server
const server = https.createServer(options, app);

// Server start
server.listen(port, () => {
  console.log(`🔒 Secure server listening on https://localhost:${port}`);
});

// Optional: Redirect HTTP to HTTPS
import http from 'http';
const httpPort = 3000;

http.createServer((req, res) => {
  res.writeHead(301, { "Location": `https://localhost:${port}${req.url}` });
  res.end();
}).listen(httpPort, () => {
  console.log(`🔄 HTTP server redirecting from http://localhost:${httpPort} to HTTPS`);
});