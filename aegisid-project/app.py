import hashlib
import io
import os
import numpy as np
from fastapi import FastAPI, File, HTTPException, UploadFile
from PIL import Image, ImageChops, ImageEnhance
from pydantic import BaseModel
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# Setup local SQLite database for instant plug-and-play testing
DATABASE_URL = "sqlite:///./aegisid.db"
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Define Database Models
class ScreeningRecord(Base):
  __tablename__ = "screening_records"
  id = Column(Integer, primary_key=True, index=True)
  filename = Column(String(255), nullable=False)
  ela_score = Column(Float, nullable=False)
  tampering_detected = Column(Boolean, default=False)
  risk_level = Column(String(20), default="LOW")
  created_at = Column(DateTime, default=datetime.datetime.utcnow)


class AuditLog(Base):
  __tablename__ = "audit_logs"
  id = Column(Integer, primary_key=True, index=True)
  action = Column(String(100), nullable=False)
  details = Column(Text, nullable=True)
  sha256_hash = Column(String(64), nullable=False)
  timestamp = Column(DateTime, default=datetime.datetime.utcnow)


Base.metadata.create_all(bind=engine)

# Initialize FastAPI App
app = FastAPI(
    title="AegisID Core - Identity & Document Defense Engine", version="1.0.0"
)


def get_db():
  db = SessionLocal()
  try:
    yield db
  finally:
    db.close()


def perform_error_level_analysis(image_bytes: bytes, quality: int = 90) -> float:
  """Performs Error Level Analysis (ELA) to detect digital tampering."""
  original = Image.open(io.BytesIO(image_bytes)).convert("RGB")
  buffer = io.BytesIO()
  original.save(buffer, "JPEG", quality=quality)
  buffer.seek(0)
  compressed = Image.open(buffer).convert("RGB")

  diff = ImageChops.difference(original, compressed)
  extrema = diff.getextrema()
  max_diff = max([ex[1] for ex in extrema])
  if max_diff == 0:
    max_diff = 1
  scale = 255.0 / max_diff
  enhanced = ImageEnhance.Brightness(diff).enhance(scale)

  gray_diff = np.array(enhanced.convert("L"))
  return float(np.mean(gray_diff))


@app.post("/api/v1/screen-document")
async def screen_document(file: UploadFile = File(...)):
  contents = await file.read()
  ela_score = perform_error_level_analysis(contents)

  tampering_threshold = 35.0
  is_tampered = ela_score > tampering_threshold
  risk_status = "HIGH" if is_tampered else "LOW"
  file_hash = hashlib.sha256(contents).hexdigest()

  # Save record to database
  db = SessionLocal()
  try:
    db_record = ScreeningRecord(
        filename=file.filename,
        ela_score=round(ela_score, 2),
        tampering_detected=is_tampered,
        risk_level=risk_status,
    )
    db.add(db_record)

    audit_entry = AuditLog(
        action="DOCUMENT_SCREENED",
        details=(
            f"File: {file.filename} | ELA Score: {round(ela_score, 2)} | Status:"
            f" {risk_status}"
        ),
        sha256_hash=file_hash,
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(db_record)
    record_id = db_record.id
  finally:
    db.close()

  return {
      "status": "success",
      "record_id": record_id,
      "filename": file.filename,
      "ela_score": round(ela_score, 2),
      "tampering_detected": is_tampered,
      "risk_level": risk_status,
      "integrity_hash": file_hash,
  }


@app.get("/health")
async def health_check():
  return {"status": "healthy", "service": "AegisID Engine Running"}