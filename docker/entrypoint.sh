#!/bin/bash
set -e

# When PASSSAGE_S3FS_MOUNT=1, mount the S3 cache bucket locally via s3fs
# before starting passsage.  Used in dev/CI docker-compose setups where the
# bucket lives in localstack.
if [ "${PASSSAGE_S3FS_MOUNT:-}" = "1" ] && [ -n "$S3_ENDPOINT_URL" ] && [ -n "$PASSSAGE_MOUNT_S3_PATH" ]; then
    bucket="${S3_BUCKET:-proxy-cache}"
    mkdir -p "$PASSSAGE_MOUNT_S3_PATH"

    echo "${AWS_ACCESS_KEY_ID:-test}:${AWS_SECRET_ACCESS_KEY:-test}" > /tmp/.passwd-s3fs
    chmod 600 /tmp/.passwd-s3fs

    # Wait for the bucket to exist (localstack init script race)
    for i in $(seq 1 30); do
        if curl -sf "${S3_ENDPOINT_URL}/${bucket}" >/dev/null 2>&1; then
            break
        fi
        echo "s3fs: waiting for bucket ${bucket}... ($i)"
        sleep 1
    done

    s3fs "$bucket" "$PASSSAGE_MOUNT_S3_PATH" \
        -o passwd_file=/tmp/.passwd-s3fs \
        -o url="$S3_ENDPOINT_URL" \
        -o use_path_request_style \
        -o allow_other

    echo "s3fs: mounted s3://$bucket at $PASSSAGE_MOUNT_S3_PATH"
fi

exec "$@"
