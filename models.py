from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin, AsaList
from werkzeug.security import generate_password_hash, check_password_hash
from database import Base
from flask_security import UserMixin, RoleMixin, AsaList
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy import Boolean, DateTime, Column, Integer, \
                    String, ForeignKey, Table

cases_users_association = Table('case_users_association', Base.metadata,
    Column('case_id', Integer, ForeignKey('case.id')),
    Column('user_id', Integer, ForeignKey('user.id'))
)

class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    username = Column(String(100), unique=True, nullable=True)
    password = Column(String(255))
    active = Column(Boolean(),default=True)
    fs_uniquifier = Column(String(64), unique=True, nullable=False)
    roles = relationship('Role', secondary='roles_users', backref=backref('users', lazy='dynamic'))
    assigned_cases = relationship('Case', secondary=cases_users_association, back_populates='assigned_users')
    
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

class Case(Base):
    __tablename__ = 'case'
    id = Column(Integer(), primary_key=True)
    name = Column(String(255))
    client = Column(String(255))
    splunk_index = Column(String(100))
    assigned_users = relationship('User', secondary=cases_users_association, back_populates='assigned_cases')