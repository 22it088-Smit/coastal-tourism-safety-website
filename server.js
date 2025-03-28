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



// Config
env.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = 3000;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
console.log('Static directory:', path.join(__dirname, 'public'));
app.use(bodyParser.urlencoded({ extended: true }))
app.set('view engine', 'ejs');

// Add session middleware after other middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
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
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            username,
            email,
            password: hashedPassword
        });
        
        await user.save();
        res.redirect('/login');
    } catch (error) {
        res.render('register', { error: 'Registration failed' });
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.render('login', { error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.render('login', { error: 'Invalid credentials' });
        }
        
        req.session.userId = user._id;
        res.redirect('/');
    } catch (error) {
        res.render('login', { error: 'Login failed' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/', requireAuth, (req, res) => {
    res.render('index.ejs', { error: error });
});

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
        res.render('map.ejs', { weather: weather_data, lat: lat, lon: lon, place: place });
    }
});

// Get hotels near a beach
app.get('/hotels', async (req, res) => {
    try {
        res.render('hotels', { 
            lat: null, 
            lon: null, 
            beach: null,
            error: null
        });
    } catch (error) {
        console.error(error);
        res.status(500).render('hotels', { error: 'Failed to load hotels' });
    }
});

app.get('/hotels/:lat/:lon', async (req, res) => {
    try {
        const { lat, lon } = req.params;
        
        console.log(`Searching for hotels near lat: ${lat}, lon: ${lon}`); // Debug log

        const response = await axios.get('https://api.geoapify.com/v2/places', {
            params: {
                categories: 'accommodation.hotel,accommodation.motel',
                filter: `circle:${lon},${lat},5000`, // 5km radius
                bias: `proximity:${lon},${lat}`,
                limit: 20,
                apiKey: process.env.GEOAPIFY_API_KEY
            }
        });

        console.log('API Response:', response.data); // Debug log

        if (!response.data.features) {
            console.log('No features in response');
            return res.json([]);
        }

        const hotels = response.data.features.map(place => ({
            name: place.properties.name || 'Unnamed Location',
            address: place.properties.formatted || 'No address available',
            distance: place.properties.distance || 0,
            coordinates: [place.properties.lon, place.properties.lat],
            _id: place.properties.place_id // Using place_id as _id
        }));

        console.log(`Found ${hotels.length} hotels`); // Debug log
        res.json(hotels);
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

// Add this route to handle hotels near a specific beach
app.get('/hotels/:lat/:lon/:beach', async (req, res) => {
    try {
        const { lat, lon, beach } = req.params;
        res.render('hotels', { 
            lat, 
            lon, 
            beach: decodeURIComponent(beach),
            error: null 
        });
    } catch (error) {
        console.error(error);
        res.status(500).render('hotels', { error: 'Failed to load hotels' });
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

// Server Start
app.listen(port, () => {
    console.log(`🌐 Listening on http://localhost:${port}`);
});