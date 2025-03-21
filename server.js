import e from "express";
import env from "dotenv";
env.config();
import path from 'path';
import { fileURLToPath } from 'url';
import axios from "axios";
import bodyParser from "body-parser";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

//! Custom JS Modules

import weather_owm from "./modules/weather_owm.mjs";
import tomorrow_weather from "./modules/tomorrow_weather.mjs";
// import weather_aqi from "./modules/weather_aqi.mjs";
import aqi_test from "./modules/aqi_test.mjs";
import marine from "./modules/marine.mjs";
// import gemini_prompt from "./modules/gemini_prompt.mjs";

const app = e();
const OWM_API = process.env.OWM_API
const port = 3000;

app.use(e.static(__dirname + '/public'))
app.use(bodyParser.urlencoded({extended:true}))

// Pre Defined Variables

var lat,lon,place,weather_data;

weather_data = {
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
}

export default weather_data;

let error = ``

app.get('/' , (req,res) => {
    res.render('index.ejs' , {error:error})
})

app.post('/find' ,async (req,res) => {
    place = req.body['place']

    try {
        const location = await axios.get(`http://api.openweathermap.org/geo/1.0/direct?q=${place}&limit=5&appid=${process.env.OWM_API}`)
        console.log(location.data);
        lat = location.data[0].lat;
        lon = location.data[0].lon;
        place = location.data[0].name;
        weather_data.city_name = place;
    } catch (error) {
        return error
    }
    // console.log(lat,lon);
    await weather_owm(lat,lon);
    await tomorrow_weather(lat,lon);
    await aqi_test(lat,lon);
    await marine(lat,lon);
    // await gemini_prompt(place)
    console.log(weather_data);

    if(weather_data.ocean.wave === 'nullm') {
        error = `The given city does not have a beach.`;
        res.redirect("/")
    } else {
        res.render('map.ejs' , {weather: weather_data ,lat: lat ,lon:lon, place:place });
    }
})

app.listen(port , () => {
    console.log("Listening on http://localhost:3000");
})

// async function weather_owm(lat,lon) {
//     // console.log(lat,lon);
//     try {
//        const response = await axios.get(`https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${OWM_API}`);
//        console.log(response.data);
//        console.log("Finished Work");
//     } catch (error) {
//         console.log(error.code);
//     }
// }
