from typing import List
from pydantic import BaseModel
from pybacked.secret_sharing.shamir import Share


class Header(BaseModel):
    id: bytes
    share: Share
    threshold: int


class Container(BaseModel):
    data: bytes


class Information(BaseModel):
    salt: bytes
    containers: List[Container]


class ShareModel(BaseModel):
    header: Header
    information: bytes
