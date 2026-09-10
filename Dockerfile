FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir '.[reports]' && useradd --uid 10001 --create-home botscope && mkdir /reports && chown botscope:botscope /reports
USER botscope
WORKDIR /work
ENTRYPOINT ["botscope"]
CMD ["--help"]
