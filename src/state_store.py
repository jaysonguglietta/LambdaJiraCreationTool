from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime


class StateStore:
    def __init__(self, dynamodb_client, table_name: str, *, retention_days: int = 90) -> None:
        self.client = dynamodb_client
        self.table_name = table_name
        self.owner = uuid.uuid4().hex
        self.retention_seconds = retention_days * 86400

    @staticmethod
    def _json(value: object, limit: int = 240_000) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        if len(encoded.encode()) > limit:
            raise ValueError("State payload too large; store complete details in an audit artifact")
        return encoded

    def get_record(self, pk: str) -> dict | None:
        item = self._get(pk)
        return json.loads(item["payload"]) if item and "payload" in item else None

    def put_record(self, pk: str, value: dict) -> None:
        item = {
            "pk": {"S": pk},
            "payload": {"S": self._json(value)},
            "state_status": {"S": str(value.get("status", "RECORDED"))},
            "state_deadline": {"N": str(value.get("deadline", int(time.time())))},
            "expires_at": {
                "N": str(
                    max(
                        int(time.time()) + self.retention_seconds,
                        int(value.get("deadline", 0)) + 7 * 86400,
                    )
                )
            },
        }
        self.client.put_item(TableName=self.table_name, Item=item)

    def list_status(self, status: str, *, before: int | None = None) -> list[dict]:
        values = {":status": {"S": status}}
        condition = "state_status = :status"
        if before is not None:
            condition += " AND state_deadline <= :before"
            values[":before"] = {"N": str(before)}
        results, cursor = [], None
        while True:
            kwargs = {
                "TableName": self.table_name,
                "IndexName": "status-index",
                "KeyConditionExpression": condition,
                "ExpressionAttributeValues": values,
                "Limit": 100,
            }
            if cursor:
                kwargs["ExclusiveStartKey"] = cursor
            response = self.client.query(**kwargs)
            results.extend(json.loads(item["payload"]["S"]) for item in response.get("Items", []))
            cursor = response.get("LastEvaluatedKey")
            if not cursor:
                return results
            if len(results) >= 1000:
                raise ValueError(
                    "Too many outstanding operational records; inspect before retrying"
                )

    def _get(self, pk: str) -> dict[str, str] | None:
        response = self.client.get_item(
            TableName=self.table_name,
            Key={"pk": {"S": pk}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not item:
            return None
        return {key: next(iter(value.values())) for key, value in item.items()}

    def get_run(self, fingerprint: str) -> dict[str, str] | None:
        return self._get(f"RUN#{fingerprint}")

    def mark_run(self, fingerprint: str, status: str, payload: dict[str, object]) -> None:
        now = datetime.now(UTC).isoformat()
        self.client.put_item(
            TableName=self.table_name,
            Item={
                "pk": {"S": f"RUN#{fingerprint}"},
                "status": {"S": status},
                "updated_at": {"S": now},
                "payload": {"S": self._json(payload)},
            },
        )

    def get_mapping(self, mapping_type: str, fingerprint: str) -> str | None:
        item = self._get(f"{mapping_type.upper()}#{fingerprint}")
        return item.get("jira_key") if item else None

    def count_unmapped(self, fingerprints: list[str], budget) -> int:
        found = set()
        for start in range(0, len(fingerprints), 100):
            request = {
                self.table_name: {
                    "Keys": [{"pk": {"S": "V2#" + fp}} for fp in fingerprints[start : start + 100]],
                    "ConsistentRead": True,
                    "ProjectionExpression": "pk,jira_key",
                }
            }
            for attempt in range(3):
                budget.require(20)
                response = self.client.batch_get_item(RequestItems=request)
                found.update(
                    item["pk"]["S"][3:]
                    for item in response.get("Responses", {}).get(self.table_name, [])
                    if item.get("jira_key")
                )
                request = response.get("UnprocessedKeys", {})
                if not request:
                    break
                if attempt == 2:
                    raise RuntimeError(
                        "Mapping lookup was throttled; retry before creating Jira work"
                    )
                time.sleep(0.2 * (attempt + 1))
        return len(set(fingerprints) - found)

    def claim_mapping(
        self,
        mapping_type: str,
        fingerprint: str,
        metadata: dict[str, object],
        *,
        lease_seconds: int = 300,
    ) -> bool:
        now_epoch = int(time.time())
        try:
            self.client.put_item(
                TableName=self.table_name,
                Item={
                    "pk": {"S": f"{mapping_type.upper()}#{fingerprint}"},
                    "status": {"S": "PENDING"},
                    "claim_expires": {"N": str(now_epoch + lease_seconds)},
                    "updated_at": {"S": datetime.now(UTC).isoformat()},
                    "metadata": {"S": self._json(metadata)},
                    "claim_owner": {"S": self.owner},
                },
                ConditionExpression=(
                    "attribute_not_exists(pk) OR claim_expires < :now OR #status = :failed"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":now": {"N": str(now_epoch)},
                    ":failed": {"S": "FAILED"},
                },
            )
            return True
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                return False
            raise

    def put_mapping(
        self,
        mapping_type: str,
        fingerprint: str,
        jira_key: str,
        metadata: dict[str, object],
    ) -> None:
        now = datetime.now(UTC).isoformat()
        self.client.put_item(
            TableName=self.table_name,
            Item={
                "pk": {"S": f"{mapping_type.upper()}#{fingerprint}"},
                "jira_key": {"S": jira_key},
                "status": {"S": "COMPLETE"},
                "updated_at": {"S": now},
                "metadata": {"S": self._json(metadata)},
            },
            ConditionExpression=(
                "attribute_not_exists(pk) OR jira_key = :key OR claim_owner = :owner "
                "OR (attribute_not_exists(jira_key) AND claim_expires < :now)"
                " OR (attribute_not_exists(jira_key) AND #status = :failed)"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":key": {"S": jira_key},
                ":owner": {"S": self.owner},
                ":now": {"N": str(int(time.time()))},
                ":failed": {"S": "FAILED"},
            },
        )

    def mapping_record(self, fingerprint: str) -> dict | None:
        item = self._get(f"V2#{fingerprint}")
        if not item:
            return None
        return {**item, "metadata": json.loads(item.get("metadata", "{}"))}

    def repair_mapping(self, fingerprint: str, approved_reason: str) -> None:
        if not approved_reason.strip() or len(approved_reason) > 1000:
            raise ValueError("A reviewed repair reason is required")
        record = self.mapping_record(fingerprint)
        if not record:
            raise ValueError("Mapping does not exist")
        metadata = {**record["metadata"], "repair_reason": approved_reason}
        self.client.update_item(
            TableName=self.table_name,
            Key={"pk": {"S": f"V2#{fingerprint}"}},
            UpdateExpression="SET #status = :failed, metadata = :metadata REMOVE jira_key",
            ConditionExpression="attribute_exists(pk) AND metadata = :before",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":failed": {"S": "FAILED"},
                ":metadata": {"S": self._json(metadata)},
                ":before": {"S": self._json(record["metadata"])},
            },
        )

    def acquire_lock(self, name: str, seconds: int = 330) -> bool:
        try:
            self.client.put_item(
                TableName=self.table_name,
                Item={
                    "pk": {"S": f"LOCK#{name}"},
                    "owner": {"S": self.owner},
                    "expires": {"N": str(int(time.time()) + seconds)},
                },
                ConditionExpression="attribute_not_exists(pk) OR expires < :now",
                ExpressionAttributeValues={":now": {"N": str(int(time.time()))}},
            )
            return True
        except Exception as exc:
            if (
                getattr(exc, "response", {}).get("Error", {}).get("Code")
                == "ConditionalCheckFailedException"
            ):
                return False
            raise

    def release_lock(self, name: str) -> None:
        self.client.delete_item(
            TableName=self.table_name,
            Key={"pk": {"S": f"LOCK#{name}"}},
            ConditionExpression="#owner = :owner",
            ExpressionAttributeNames={"#owner": "owner"},
            ExpressionAttributeValues={":owner": {"S": self.owner}},
        )
