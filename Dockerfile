# Сборка и запуск в Linux-контейнере (удобно для Windows/macOS через Docker Desktop).
# Сеть для первой сборки: FetchContent тянет Catch2 с GitHub.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    build-essential \
    cmake \
    libssl-dev \
    python3 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVSECURE_BUILD_TESTS=ON \
  && cmake --build build -j"$(nproc)"

ENV PATH="/app/build:${PATH}"

# По умолчанию — shell для ручного демо (gen_keys + receiver/sender).
CMD ["/bin/bash", "-lc", "echo 'В контейнере: ./scripts/gen_keys.sh затем vsecure_receiver / vsecure_sender (см. docs/HANDOFF.md)'; exec bash"]
