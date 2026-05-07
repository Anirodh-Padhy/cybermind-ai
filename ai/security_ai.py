import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi3"

def generate_security_explanation(log_data):

    prompt = f"""
You are an expert cybersecurity analyst.

Analyze the following security event and explain:

1. What suspicious activity is happening
2. Possible attack type
3. Risk level
4. Recommended action

Security Event:
{log_data}

Provide a concise professional explanation.
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            }
        )

        return response.json().get("response", "")

    except Exception as e:
        return f"AI Error: {str(e)}"