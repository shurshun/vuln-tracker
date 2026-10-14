"""Report objects in the S3 bucket."""

import json
from collections.abc import Iterator
from datetime import datetime

import boto3


class Bucket:
    def __init__(self, name: str):
        self.name = name
        self.s3 = boto3.client("s3")

    def list(self, prefix: str) -> Iterator[tuple[str, datetime]]:
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.name, Prefix=prefix):
            for obj in page.get("Contents", []):
                yield obj["Key"], obj["LastModified"]

    def get_json(self, key: str) -> dict | None:
        try:
            body = self.s3.get_object(Bucket=self.name, Key=key)["Body"].read()
        except self.s3.exceptions.NoSuchKey:
            return None
        return json.loads(body)
