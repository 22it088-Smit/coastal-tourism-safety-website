import mongoose from "mongoose";

const beachSchema = new mongoose.Schema({
    city_name: String,
    lat: Number,
    lon: Number,
    weather_icon: String,
    aqi: {
        aqi: String,
        category: String
    },
    temp: String,
    feels_like: String,
    wind_speed: String,
    wind_dir: String,
    visibility: String,
    rain: String,
    humid: String,
    uvi: String,
    weather_desc: String,
    ocean: {
        swell: String,
        wave: String,
        m_hazard: String
    },
    beach_desc: String
}, { timestamps: true });

const Beach = mongoose.model("Beach", beachSchema);

export default Beach;
