from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import DatabaseAdapter

# Setup password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define the API Router
router = APIRouter(prefix="/auth", tags=["Authentication"])

db = DatabaseAdapter()

# --- Pydantic Models ---
class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: str

# --- Helper Functions ---
def get_password_hash(password: str) -> str:
    """Hashes a plain text password."""
    return pwd_context.hash(password)

# --- Route Handler ---
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegisterSchema):
    """
    Handles user registration by hashing the password and 
    persisting the user data via the Database Adapter.
    """
    # 1. Hash the plain text password
    hashed_password = get_password_hash(user_data.password)

    try:
        # 2. Call the database adapter to save the record
        new_user = db.save_user(
            email=user_data.email, 
            hashed_password=hashed_password
        )
        
        # 3. Return the response (excluding the password)
        return {
            "message": "User created successfully",
            "user": {
                "email": new_user["email"],
                "id": new_user["id"]
            }
        }
    except Exception as e:
        # Generic error handling for the simulation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not register user"
        )
