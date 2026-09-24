"""容器和快照检查使用的冒烟验收命令。"""

from __future__ import annotations

import argparse
import json

from .service import PhotonService


def run() -> dict:
    service = PhotonService()
    service.bootstrap_admin()
    admin = service.auth.login("admin", "photon-admin")
    service.create_user(admin, "qa-1", "quality-pass", "quality")
    qa = service.auth.login("qa-1", "quality-pass")
    service.create_lot(admin, "LOT-DEMO", "CMOS image sensor", "P3.2", 10)
    for wavelength, response in ((450, .71), (520, .93), (650, .84)):
        service.add_measurement(admin, "LOT-DEMO", wavelength, response, .01, "spectrometer-1")
    result = service.analyze(admin, "LOT-DEMO")
    service.review(qa, "LOT-DEMO", "pass", "spectrum within spec")
    lot = service.approve(qa, "LOT-DEMO", "release", "quality review passed")
    chain = service.audit_chain(admin)
    return {
        "status": "ok",
        "lot": result["lot_id"],
        "peak": result["spectrum"]["peak_wavelength_nm"],
        "lot_status": lot["status"],
        "events": len(service.audit(admin, "LOT-DEMO")),
        "chain_valid": chain["valid"],
        "head_hash": chain["head_hash"],
    }


def main() -> None:
    argparse.ArgumentParser().parse_args()
    print(json.dumps(run(), ensure_ascii=False))


if __name__ == "__main__":
    main()
