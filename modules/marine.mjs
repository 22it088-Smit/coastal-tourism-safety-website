import axios from "axios";
import env from "dotenv";
env.config();

import { weather_data } from "../server.js";

async function marine(lat,lon) {
    try {
        const response = await axios.get(`https://marine-api.open-meteo.com/v1/marine?latitude=${lat}&longitude=${lon}&current=swell_wave_height,wave_height&timezone=auto`)
        const data = response.data;

        const unit = data.current_units.wave_height

        weather_data.ocean.swell = data.current.swell_wave_height? this : 0
        weather_data.ocean.wave = data.current.wave_height
    } catch (error) {
        console.log(error);
        
    }
}

export default marine;