from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(40), nullable=False, default="user")
    is_admin = Column(Boolean, nullable=False, default=False)
    internal_notes = Column(Text, nullable=True)
    account_status = Column(String(40), nullable=False, default="active")

    orders = relationship("Order", back_populates="user")


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    product = Column(String(180), nullable=False)
    price = Column(Float, nullable=False)
    status = Column(String(80), nullable=False)
    shipping_address = Column(String(255), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    user = relationship("User", back_populates="orders")
