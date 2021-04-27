docker run -d \
  --name annexa \
  --mount type=bind,source="$(pwd)"/logs,target=/app/logs \
  annexa:latest