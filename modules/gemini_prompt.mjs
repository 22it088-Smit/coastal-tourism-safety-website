import { GoogleGenerativeAI } from "@google/generative-ai";
import env from "dotenv";
env.config();

import weather_data from "../server.js";

const API_KEY = process.env.GEMINI_API


async function gemini_prompt(city_name) {
    const genAI = new GoogleGenerativeAI(API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = "Tell Me specialities about" + city_name + " beach, describe in 500 words, write in html but only the body section";

    const result = (await model.generateContent(prompt));
    weather_data.beach_desc = (result.response.text());
}

export default gemini_prompt;