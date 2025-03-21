import axios from "axios";
import env from "dotenv";
env.config();

import weather_data from "../server.js";

const OWM_API = process.env.OWM_API;

async function weather_aqi(lat,lon) {
    try {
        const response = await axios.get(`http://api.openweathermap.org/data/2.5/air_pollution?lat=${lat}&lon=${lon}&appid=${OWM_API}`)
        const data = response.data.list[0].main.aqi;

        weather_data.aqi = data;

        // if(data = )

        console.log(data);
        console.log("AQI Call Made");
    } catch (error ) {
        return error;
        console.log("aqi call error");
    }
}

export default weather_aqi;