from google import genai
import os

api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    raise RuntimeError("GEMINI_API_KEY is not set.")

client = genai.Client(api_key=api_key)

print("API key detected.")
print("Testing Gemini API...")

response = client.models.generate_content(
    model="gemini-3.7-flash",
    contents="Reply with exactly: CYBER-EW GEMINI CONNECTION OK",
)

print("Response received:")
print(response.text)