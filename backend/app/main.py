from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()

app = FastAPI(title="Secure Password Manager API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Auth, session and vault routes land in Checkpoint 2 (see docs/checkpoint-1-design.md).
