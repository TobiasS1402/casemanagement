from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin, AsaList
from werkzeug.security import generate_password_hash, check_password_hash
from database import Base
from flask_security import UserMixin, RoleMixin, AsaList
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy import Boolean, DateTime, Column, Integer, \
                    String, ForeignKey

class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True)
    password = Column(String(255))
    active = Column(Boolean(),default=True)
    fs_uniquifier = Column(String(64), unique=True, nullable=False)
    roles = relationship('Role', secondary='roles_users', backref=backref('users', lazy='dynamic'))

class Role(Base, RoleMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255))
    permissions = Column(MutableList.as_mutable(AsaList()), nullable=True)

class RolesUsers(Base):
    __tablename__ = 'roles_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column(Integer(), ForeignKey('user.id'))
    role_id = Column(Integer(), ForeignKey('role.id'))

# Add any other models or associations you need
