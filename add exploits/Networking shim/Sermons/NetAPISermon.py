import asyncio
from fastapi import FastAPI
import uvicorn
from project import project_run

app = FastAPI()

# FastAPI route
@app.get("/")
async def read_root():
    return {"message": "FastAPI is running!"}

async def start_app():
    print("Creating Project and FastAPI tasks...")

    project_task = asyncio.create_task(project_run())
    fastapi_task = asyncio.create_task(uvicorn.run(app, host="0.0.0.0", port=8000))

    await asyncio.gather(project_task, fastapi_task)

if __name__ == "__main__":
    asyncio.run(start_app())
