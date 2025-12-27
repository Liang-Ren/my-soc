import json
import logging
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    # This stub just logs that an approval was received. You can extend it to
    # perform real IAM rollback logic based on query parameters or a finding ID.
    logger.info("Received IAM rollback approval event: %s", json.dumps(event))

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": "IAM privilege rollback approval received. (Stub)",
    }
