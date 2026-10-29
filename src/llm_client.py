import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def load_config():
    # Recharge la configuration enregistrée dans l'interface.
    load_dotenv(dotenv_path=ENV_FILE, override=True)


def create_client() -> OpenAI:
    load_config()
    provider = os.getenv("LLM_PROVIDER", "groq").strip().lower()

    if provider == "groq":
        api_key = os.getenv("GROQ_API_KEY") or os.getenv("LLM_API_KEY")
        if not api_key:
            raise RuntimeError(
                "Clé API absente. Configure GROQ_API_KEY dans le fichier .env."
            )
        base_url = os.getenv(
            "LLM_BASE_URL",
            "https://api.groq.com/openai/v1",
        )
        return OpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=30.0,
            max_retries=0,
        )

    if provider == "ollama":
        base_url = os.getenv(
            "LLM_BASE_URL",
            "http://localhost:11434/v1",
        )
        api_key = os.getenv("LLM_API_KEY", "ollama")
        return OpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=120.0,
            max_retries=0,
        )

    raise RuntimeError(
        f"Fournisseur IA inconnu : {provider}. Utilise 'groq' ou 'ollama'."
    )


def ask_model(prompt: str) -> str:
    if not prompt.strip():
        raise ValueError("Le prompt ne doit pas être vide.")

    load_config()
    provider = os.getenv("LLM_PROVIDER", "groq").strip().lower()
    default_model = (
        "openai/gpt-oss-20b" if provider == "groq" else "llama3.2:3b"
    )
    model = os.getenv("LLM_MODEL", default_model)

    client = create_client()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        max_tokens=1800,
    )

    content = response.choices[0].message.content
    if not content or not content.strip():
        raise RuntimeError(f"Le modèle {model} a renvoyé une réponse vide.")

    return content.strip()
