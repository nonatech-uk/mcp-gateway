FROM mcp-search:latest

WORKDIR /app/gateway

COPY pyproject.toml .
COPY src/ src/
RUN uv pip install --system --no-cache .

ENTRYPOINT ["python", "-m"]
CMD ["mcp_gateway.server"]
