"""Development server entry point."""

import uvicorn


def main() -> None:
    """Run the FastAPI app for local development."""

    uvicorn.run("incidentsight.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
