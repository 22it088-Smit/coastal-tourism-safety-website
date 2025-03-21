import axios from "axios";
import env from "dotenv";
env.config();

import weather_data from "../server.js";

const OWM_API = process.env.OWM_API;

async function aqi_test(lat, lon) {
    const response = await axios.get(`http://api.openweathermap.org/data/2.5/air_pollution?lat=${lat}&lon=${lon}&appid=${OWM_API}`)
    const data = response.data.list[0];
    // console.log(data);

    function calculateAQI(concentration, breakpoints) {
        const [C_low, C_high, I_low, I_high] = breakpoints;

        // Calculate the AQI using the formula
        return Math.round(((I_high - I_low) / (C_high - C_low)) * (concentration - C_low) + I_low);
    }

    function determineAQI(pollutionData) {
        const breakpoints = {
            pm2_5: [
                [0.0, 12.0, 0, 50],
                [12.1, 35.4, 51, 100],
                [35.5, 55.4, 101, 150],
                [55.5, 150.4, 151, 200],
                [150.5, 250.4, 201, 300],
                [250.5, 350.4, 301, 400],
                [350.5, 500.4, 401, 500],
            ],
            pm10: [
                [0, 54, 0, 50],
                [55, 154, 51, 100],
                [155, 254, 101, 150],
                [255, 354, 151, 200],
                [355, 424, 201, 300],
                [425, 504, 301, 400],
                [505, 604, 401, 500],
            ],
            // Add other pollutants like O3, CO, NO2, and SO2 here if needed
        };

        const pollutants = {
            pm2_5: pollutionData.list[0].components.pm2_5,
            pm10: pollutionData.list[0].components.pm10,
            // Add other pollutant data here
        };

        let overallAQI = 0;
        const aqiResults = {};

        for (const [pollutant, concentration] of Object.entries(pollutants)) {
            const pollutantBreakpoints = breakpoints[pollutant];
            for (const bp of pollutantBreakpoints) {
                if (concentration >= bp[0] && concentration <= bp[1]) {
                    const aqi = calculateAQI(concentration, bp);
                    aqiResults[pollutant] = aqi;
                    overallAQI = Math.max(overallAQI, aqi);
                    break;
                }
            }
        }

        aqiResults.overall = overallAQI;
        return aqiResults;
    }



    // Example usage:
    // Replace this with the actual data from OpenWeatherMap API response
    const exampleData = {
        list: [
            {
                components: {
                    pm2_5: data.components.pm2_5,
                    pm10: data.components.pm10,
                    // Include other components as necessary
                },
            },
        ],
    };

    const aqi = determineAQI(exampleData);

    let category;
    if (aqi.overall <= 50) category = "Good";
    else if (aqi.overall <= 100) category = "Moderate";
    else if (aqi.overall <= 150) category = "Unhealthy for Sensitive Groups";
    else if (aqi.overall <= 200) category = "Unhealthy";
    else if (aqi.overall <= 300) category = "Very Unhealthy";
    else category = "Hazardous";

    weather_data.aqi.aqi = aqi.overall
    weather_data.aqi.category = category
    console.log(aqi);
    
}

export default aqi_test;

