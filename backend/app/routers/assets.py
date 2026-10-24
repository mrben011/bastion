import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, require
from ..models import Asset
from ..schemas import AssetIn, AssetOut, AssetUpdateIn

router = APIRouter(prefix="/api/assets", tags=["assets"])


def _get(db: Session, ctx: AuthContext, asset_id: uuid.UUID) -> Asset:
    asset = db.execute(select(Asset).where(Asset.id == asset_id, Asset.org_id == ctx.org_id)).scalar_one_or_none()
    if not asset:  # other organizations' assets are indistinguishable from missing ones
        raise HTTPException(404, {"code": "not_found", "message": "Asset not found."})
    return asset


def _audit(db: Session, ctx: AuthContext, action: str, asset: Asset, details: dict | None = None) -> None:
    audit.record(db, org_id=ctx.org_id, action=action, actor_user_id=ctx.user.id, actor_label=ctx.user.email,
                 target_type="asset", target_id=str(asset.id), ip=ctx.ip, user_agent=ctx.ua, details=details)


@router.get("", response_model=list[AssetOut])
def list_assets(
    q: str | None = Query(default=None, max_length=100),
    asset_type: str | None = Query(default=None, max_length=40),
    environment: str | None = Query(default=None, max_length=20),
    ctx: AuthContext = Depends(require("assets:read")),
    db: Session = Depends(get_db),
):
    stmt = select(Asset).where(Asset.org_id == ctx.org_id)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(Asset.name.ilike(f"%{escaped}%", escape="\\"))
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if environment:
        stmt = stmt.where(Asset.environment == environment)
    return db.execute(stmt.order_by(Asset.name).limit(200)).scalars().all()


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: uuid.UUID, ctx: AuthContext = Depends(require("assets:read")), db: Session = Depends(get_db)):
    return _get(db, ctx, asset_id)


@router.post("", response_model=AssetOut, status_code=201)
def register_asset(body: AssetIn, ctx: AuthContext = Depends(require("assets:write")), db: Session = Depends(get_db)):
    asset = Asset(org_id=ctx.org_id, created_by=ctx.user.id, **body.model_dump())
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, {"code": "name_in_use", "message": "An asset with that name already exists."})
    _audit(db, ctx, "asset.registered", asset, {"name": asset.name, "asset_type": asset.asset_type, "environment": asset.environment})
    db.commit()
    return asset


@router.put("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: uuid.UUID, body: AssetUpdateIn, ctx: AuthContext = Depends(require("assets:write")),
                 db: Session = Depends(get_db)):
    asset = _get(db, ctx, asset_id)
    changed = [k for k, v in body.model_dump().items() if getattr(asset, k) != v]
    for k, v in body.model_dump().items():
        setattr(asset, k, v)
    asset.updated_at = datetime.now(timezone.utc)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, {"code": "name_in_use", "message": "An asset with that name already exists."})
    _audit(db, ctx, "asset.updated", asset, {"fields_changed": ",".join(changed)})
    db.commit()
    return asset


@router.delete("/{asset_id}")
def remove_asset(asset_id: uuid.UUID, ctx: AuthContext = Depends(require("assets:write")), db: Session = Depends(get_db)):
    asset = _get(db, ctx, asset_id)
    _audit(db, ctx, "asset.removed", asset, {"name": asset.name})
    db.delete(asset)
    db.commit()
    return {"ok": True}
