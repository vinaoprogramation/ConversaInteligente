import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "mysql+aiomysql://root:escola@localhost:3306/conversa_inteligente_db"

engine = create_async_engine(DATABASE_URL, echo = True)

SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

async def get_db():
    async with SessionLocal() as session:
        yield session
