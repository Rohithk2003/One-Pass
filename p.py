import pyAesCrypt
"------------------------------------importing modules------------------------------------"
import math
import pickle
import random
import smtplib
from tkinter import *
import glob
import pyAesCrypt
import mysql.connector
import os
import sys
from tkinter import messagebox
import os.path
import atexit

from tkinter.ttk import *
from cryptography.fernet import Fernet
from datetime import datetime
from geopy.geocoders import Nominatim
import geocoder
import socket
from time import gmtime, strftime
import hashlib
import base64
from passlib.hash import pbkdf2_sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pygame

a = '12345' + 'rohith'
main = hashlib.sha512(a.encode()).hexdigest()
def hi():
    return False,'hi'
d,b = hi()
print(d,b)
