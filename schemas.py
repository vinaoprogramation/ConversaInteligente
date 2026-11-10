from pydantic import BaseModel, EmailStr, ConfigDict

class UsuarioBase(BaseModel):
    name: str
    email: EmailStr
    password: str

class UsuarioCreate(UsuarioBase):
    pass

class UsuarioResponse(UsuarioBase):
    id: int

    model_config = ConfigDict(from_attributes=True)