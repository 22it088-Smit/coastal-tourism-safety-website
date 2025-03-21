import axios from "axios";
import env from "dotenv";
env.config();

import weather_data from "../server.js";

const TOMORROW_API = process.env.TOMORROW_API

async function tomorrow_weather(lat,lon) {
    try {
        const response = await axios.get(`https://api.tomorrow.io/v4/weather/realtime?apikey=${TOMORROW_API}&location=${lat},${lon}&timezone=Asia/kolkata`)
        const data =  response.data;
        // console.log(data);

        weather_data.rain = data.data.values.precipitationProbability;
        weather_data.humid = data.data.values.humidity;
        weather_data.uvi = data.data.values.uvIndex;
        weather_data.visibility = (data.data.values.visibility)
    } catch (error) {
        console.log(error);
    }
}

export default tomorrow_weather;