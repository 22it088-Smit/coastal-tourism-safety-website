import e from "express";
import env from "dotenv";
env.config();
import path from 'path';
import { fileURLToPath } from 'url';
import axios from "axios";
import bodyParser from "body-parser";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = e();
const API_KEY = process.env.API_KEY
const port = 3000;

app.use(e.static(__dirname + '/public'))
app.use(bodyParser.urlencoded({extended:true}))

const airPollution = async (lat,lon) => {
    try {
        const response =await axios.get(`http://api.openweathermap.org/data/2.5/air_pollution?lat=${lat}&lon=${lon}&appid=${process.env.OPM_API}`)
        console.log(response.data);
    } catch (error) {
        console.log("error");
    }
}

airPollution(28.7041,77.1025);