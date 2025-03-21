import axios from "axios";
import env from "dotenv";
env.config();

import weather_data from "../server.js";

const OWM = process.env.OWM_API;

async function weather_owm(lat,lon) {
    // console.log(lat,lon);
    try {
       const response = await axios.get(`https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&units=metric&appid=${OWM}`);
       const data = response.data;
    //    console.log(data);

       weather_data.weather_icon = data.weather[0].icon;
       weather_data.temp = data.main.temp;
       weather_data.feels_like = data.main.feels_like;
       weather_data.wind_speed = data.wind.speed;
       weather_data.wind_dir = data.wind.deg;
       weather_data.weather_desc = data.weather[0].description;
    } catch (error) {
        console.log(error.code);
    }
}

export default weather_owm;