import axios from "axios";
import env from "dotenv";
env.config();

async function co_ords(place) {
    try {
        const location = await axios.get(`http://api.openweathermap.org/geo/1.0/direct?q=${place}&limit=5&appid=${process.env.OWM_API}`)
        // console.log(location.data);
        lat = location.data[0].lat;
        lon = location.data[0].lon;
        place = location.data[0].name;
    } catch (error) {
        return error
    }
}

export default co_ords;