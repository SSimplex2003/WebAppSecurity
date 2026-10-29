from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .crypto import decrypt_item, encrypt_item
from .db import get_db
from .deps import AuthContext, get_auth, require_csrf
from .models import VaultItem, utcnow
from .schemas import ItemIn, ItemOut

router = APIRouter(prefix="/api/vault", tags=["vault"])

_FIELDS = ("title", "username", "password", "url", "notes")


def _serialize(item: VaultItem, fields: dict) -> ItemOut:
    return ItemOut(
        id=item.id,
        created_at=item.created_at,
        updated_at=item.updated_at,
        **{name: fields.get(name, "") for name in _FIELDS},
    )


def _decrypt(item: VaultItem, ctx: AuthContext) -> ItemOut:
    try:
        fields = decrypt_item(ctx.key, item.user_id, item.ciphertext, item.nonce, item.auth_tag)
    except InvalidTag:
        audit.error("decrypt_failed user_id=%s item_id=%s", item.user_id, item.id)
        raise HTTPException(status_code=500, detail="A stored item could not be decrypted")
    return _serialize(item, fields)


def _owned_item(db: Session, ctx: AuthContext, item_id: int) -> VaultItem:
    # Always scoped by the session's user id; another user's item looks missing.
    item = db.scalar(
        select(VaultItem).where(VaultItem.id == item_id, VaultItem.user_id == ctx.user_id)
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@router.get("/items", response_model=list[ItemOut])
def list_items(ctx: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(VaultItem).where(VaultItem.user_id == ctx.user_id).order_by(VaultItem.id)
    ).all()
    return [_decrypt(row, ctx) for row in rows]


@router.post("/items", response_model=ItemOut, status_code=201)
def create_item(
    body: ItemIn, ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)
):
    fields = body.model_dump()
    ciphertext, nonce, tag = encrypt_item(ctx.key, ctx.user_id, fields)
    item = VaultItem(user_id=ctx.user_id, ciphertext=ciphertext, nonce=nonce, auth_tag=tag)
    db.add(item)
    db.commit()
    audit.info("item_created user_id=%s item_id=%s", ctx.user_id, item.id)
    return _serialize(item, fields)


@router.put("/items/{item_id}", response_model=ItemOut)
def update_item(
    item_id: int,
    body: ItemIn,
    ctx: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    item = _owned_item(db, ctx, item_id)
    fields = body.model_dump()
    item.ciphertext, item.nonce, item.auth_tag = encrypt_item(ctx.key, ctx.user_id, fields)
    item.updated_at = utcnow()
    db.commit()
    audit.info("item_updated user_id=%s item_id=%s", ctx.user_id, item.id)
    return _serialize(item, fields)


@router.delete("/items/{item_id}", status_code=204)
def delete_item(
    item_id: int, ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)
):
    item = _owned_item(db, ctx, item_id)
    db.delete(item)
    db.commit()
    audit.info("item_deleted user_id=%s item_id=%s", ctx.user_id, item_id)
    return Response(status_code=204)
