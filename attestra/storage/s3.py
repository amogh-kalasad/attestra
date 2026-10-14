"""S3 / SeaweedFS storage backend (optional boto3)."""

from __future__ import annotations

from attestra import config
from attestra.storage.local import StorageError


class S3Storage:
    """Object storage with Object Lock when the bucket supports it.

    Requires ``boto3`` and ``ATTESTRA_S3_BUCKET``. Marked integration in tests.
    """

    def __init__(self):
        try:
            import boto3
        except ImportError as exc:
            raise StorageError("boto3 is required for S3 storage; pip install attestra[s3]") from exc
        bucket = config.S3_BUCKET
        if not bucket:
            raise StorageError("ATTESTRA_S3_BUCKET is required for S3 storage")
        self.bucket = bucket
        kwargs = {}
        if config.S3_ENDPOINT:
            kwargs["endpoint_url"] = config.S3_ENDPOINT
        self.client = boto3.client("s3", **kwargs)

    def put(self, key: str, data: bytes) -> str:
        uri = f"s3://{self.bucket}/{key}"
        if self.exists(uri):
            try:
                if self.get(uri) == data:
                    return uri
            except Exception:
                pass
            raise StorageError(f"refusing overwrite of existing object: {key}")
        extra = {}
        if config.S3_OBJECT_LOCK:
            extra["ObjectLockMode"] = "COMPLIANCE"
            # Retention days left to bucket default when not set
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, **extra)
        return uri

    def get(self, uri: str) -> bytes:
        bucket, key = self._parse(uri)
        obj = self.client.get_object(Bucket=bucket, Key=key)
        return obj["Body"].read()

    def exists(self, uri: str) -> bool:
        bucket, key = self._parse(uri)
        try:
            self.client.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def _parse(self, uri: str) -> tuple[str, str]:
        if uri.startswith("s3://"):
            rest = uri[5:]
            bucket, _, key = rest.partition("/")
            return bucket, key
        return self.bucket, uri
