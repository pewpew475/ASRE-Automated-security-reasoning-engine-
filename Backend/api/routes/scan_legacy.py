from fastapi import APIRouter, Depends

from api.deps import DBSession, get_scan_or_404
from models.scan import Scan

from .scan import delete_scan

router = APIRouter()


@router.delete("/{scan_id}", include_in_schema=False)
async def delete_scan_legacy(
    db: DBSession,
    scan: Scan = Depends(get_scan_or_404),
) -> dict[str, str]:
    # Backward-compatible delete route for clients still calling /api/scans/{scan_id}.
    return await delete_scan(db=db, scan=scan)
