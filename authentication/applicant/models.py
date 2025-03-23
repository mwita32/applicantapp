import re
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.exceptions import ValidationError

# Function to validate registration number format
def validate_reg_number(value):
    pattern = r'^[A-Z]{3}/[A-Z]/01-\d{5}/\d{4}$'
    if not re.match(pattern, value):
        raise ValidationError(
            "Registration number must follow the format: ABC/X/01-XXXXX/YYYY (e.g., SIT/B/01-55559/2022)."
        )

# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, reg_number, email, full_name, password=None):
        if not reg_number:
            raise ValueError("Users must have a registration number")
        if not email:
            raise ValueError("Users must have an email address")

        email = self.normalize_email(email)
        user = self.model(
            reg_number=reg_number, email=email, full_name=full_name, is_applicant=True
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, reg_number, email, full_name, password):
        user = self.create_user(reg_number, email, full_name, password)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True  # Superuser should always be active
        user.is_applicant = False  # Superusers are not applicants
        user.save(using=self._db)
        return user

# Custom User Model
class CustomUser(AbstractBaseUser, PermissionsMixin):
    reg_number = models.CharField(
        max_length=20,  # Keep within MySQL index limits
        unique=True,
        verbose_name="Registration Number",
        validators=[validate_reg_number],
        db_index=False  # Prevents automatic index issues
    )
    email = models.EmailField(
        max_length=191,  # Adjusted to prevent index key issues
        unique=True,
        verbose_name="Email Address"
    )
    full_name = models.CharField(max_length=100, verbose_name="Full Name")
    is_active = models.BooleanField(default=False)  # Require email verification
    is_staff = models.BooleanField(default=False)   # Required for admin access
    is_applicant = models.BooleanField(default=True)  # Added to fix admin.py issue
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'reg_number'  # User logs in using reg_number
    REQUIRED_FIELDS = ['email', 'full_name']

    def __str__(self):
        return f"{self.full_name} ({self.reg_number})"
