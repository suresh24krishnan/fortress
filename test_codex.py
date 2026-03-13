from dotenv import load_dotenv
from openai import OpenAI
import os

# Load environment variables
load_dotenv()

# Initialize client
client = OpenAI()

# Test Codex with GPT-3.5 Turbo
try:
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": "Write a Python function called hello_world that prints Hello, World!"}
        ],
        max_tokens=150
    )
    print("✓ Codex is working!")
    print(response.choices[0].message.content)
except Exception as e:
    print(f"✗ Error: {e}")