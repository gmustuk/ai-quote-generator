import {Request, Response} from "express";
import { generatePrompt } from "../../utils/openai.utils";
import {generateImage} from "../../utils/unsplash.utils";


export async function generatePromptController(request: Request, response: Response) {

    try {
        const { topicValue, voiceValue } = request.body;

        // const quote = await generatePrompt(topicValue, voiceValue);
        const quote = "Do or do not - Robert Yoda"
        const imageData = await generateImage(topicValue);

        const data = {quote, imageData}

        // console.log(data)

        return response.json({ status: 200, message: "success", data });
    } catch (error) {
        response.json({ status: 500, message: 'Error generating prompt', data: null });
    }
}

