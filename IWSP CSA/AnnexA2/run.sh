docker run -d \
  -- it \
  --name annexa \
  --mount type=bind,source="$(pwd)"/logs,target=/app/logs \
  -p 80:80 \
  annexa:latest