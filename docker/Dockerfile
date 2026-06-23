ARG REGISTRY_MIRROR=docker.io
FROM ${REGISTRY_MIRROR}/library/rust:1.95-bookworm AS builder

ARG USE_CHINA_MIRROR=false
ARG APT_MIRROR=mirrors.tuna.tsinghua.edu.cn

RUN if [ "$USE_CHINA_MIRROR" = "true" ]; then \
        sed -i "s/deb.debian.org/${APT_MIRROR}/g" /etc/apt/sources.list.d/debian.sources || \
        sed -i "s/deb.debian.org/${APT_MIRROR}/g" /etc/apt/sources.list || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends cmake build-essential pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/cargo/.cargo && \
    if [ "$USE_CHINA_MIRROR" = "true" ]; then \
        echo '[source.crates-io]' > /usr/local/cargo/.cargo/config.toml ; \
        echo 'replace-with = "ustc-sparse"' >> /usr/local/cargo/.cargo/config.toml ; \
        echo '' >> /usr/local/cargo/.cargo/config.toml ; \
        echo '[source.ustc-sparse]' >> /usr/local/cargo/.cargo/config.toml ; \
        echo 'registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"' >> /usr/local/cargo/.cargo/config.toml ; \
        echo '' >> /usr/local/cargo/.cargo/config.toml ; \
        echo '[source.rsproxy-sparse]' >> /usr/local/cargo/.cargo/config.toml ; \
        echo 'registry = "sparse+https://rsproxy.cn/index/"' >> /usr/local/cargo/.cargo/config.toml ; \
        echo '' >> /usr/local/cargo/.cargo/config.toml ; \
        echo '[net]' >> /usr/local/cargo/.cargo/config.toml ; \
        echo 'git-fetch-with-cli = true' >> /usr/local/cargo/.cargo/config.toml ; \
        echo 'retry = 10' >> /usr/local/cargo/.cargo/config.toml ; \
        echo 'timeout = 120' >> /usr/local/cargo/.cargo/config.toml ; \
    fi

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY crates/funmail-common/Cargo.toml crates/funmail-common/Cargo.toml
COPY crates/funmail-smtp/Cargo.toml crates/funmail-smtp/Cargo.toml
COPY crates/funmail-pop3/Cargo.toml crates/funmail-pop3/Cargo.toml
COPY crates/funmail-imap/Cargo.toml crates/funmail-imap/Cargo.toml
COPY crates/funmail-delivery/Cargo.toml crates/funmail-delivery/Cargo.toml
COPY crates/funmail-admin/Cargo.toml crates/funmail-admin/Cargo.toml

RUN mkdir -p crates/funmail-common/src && echo "" > crates/funmail-common/src/lib.rs && \
    mkdir -p crates/funmail-smtp/src && echo "fn main(){}" > crates/funmail-smtp/src/main.rs && \
    mkdir -p crates/funmail-pop3/src && echo "fn main(){}" > crates/funmail-pop3/src/main.rs && \
    mkdir -p crates/funmail-imap/src && echo "fn main(){}" > crates/funmail-imap/src/main.rs && \
    mkdir -p crates/funmail-delivery/src && echo "fn main(){}" > crates/funmail-delivery/src/main.rs && \
    mkdir -p crates/funmail-admin/src && echo "fn main(){}" > crates/funmail-admin/src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release || true

COPY sql/ sql/
COPY crates/ crates/

# 清理可能残留的旧文件（api.rs 与 api/mod.rs 不能同时存在）
RUN rm -f crates/funmail-admin/src/api.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    mkdir -p /app/release-bin && \
    cp /app/target/release/funmail-smtp \
       /app/target/release/funmail-pop3 \
       /app/target/release/funmail-imap \
       /app/target/release/funmail-delivery \
       /app/target/release/funmail-admin \
       /app/release-bin/

FROM ${REGISTRY_MIRROR}/library/debian:bookworm-slim AS runtime

ARG USE_CHINA_MIRROR=false
ARG APT_MIRROR=mirrors.tuna.tsinghua.edu.cn

RUN if [ "$USE_CHINA_MIRROR" = "true" ]; then \
        sed -i "s/deb.debian.org/${APT_MIRROR}/g" /etc/apt/sources.list.d/debian.sources || \
        sed -i "s/deb.debian.org/${APT_MIRROR}/g" /etc/apt/sources.list || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates openssl libcap2-bin && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r funmail && useradd -r -g funmail -s /sbin/nologin funmail

COPY --from=builder /app/release-bin/funmail-smtp /usr/local/bin/funmail-smtp
COPY --from=builder /app/release-bin/funmail-pop3 /usr/local/bin/funmail-pop3
COPY --from=builder /app/release-bin/funmail-imap /usr/local/bin/funmail-imap
COPY --from=builder /app/release-bin/funmail-delivery /usr/local/bin/funmail-delivery
COPY --from=builder /app/release-bin/funmail-admin /usr/local/bin/funmail-admin

RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/funmail-smtp && \
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/funmail-pop3 && \
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/funmail-imap && \
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/funmail-admin

COPY frontend/index.html /etc/funmail/frontend/index.html
COPY frontend/src/ /etc/funmail/frontend/src/
COPY frontend/webmail/ /etc/funmail/frontend/webmail/

# 添加缓存破坏版本号，确保浏览器加载最新前端文件
RUN BUILD_TS=$(date +%s) && \
    sed -i "s/\.js\"/\.js?v=${BUILD_TS}\"/g" /etc/funmail/frontend/index.html && \
    sed -i "s/\.js\"/\.js?v=${BUILD_TS}\"/g" /etc/funmail/frontend/webmail/index.html && \
    sed -i "s/\.css\"/\.css?v=${BUILD_TS}\"/g" /etc/funmail/frontend/index.html && \
    sed -i "s/\.css\"/\.css?v=${BUILD_TS}\"/g" /etc/funmail/frontend/webmail/index.html

COPY sql/schema.sql /etc/funmail/schema.sql
COPY sql/logs_schema.sql /etc/funmail/logs_schema.sql

RUN mkdir -p /etc/funmail /var/log/funmail /var/lib/funmail/maildir && \
    chown -R funmail:funmail /etc/funmail /var/log/funmail /var/lib/funmail

USER funmail

EXPOSE 25 110 143 993 995 10002

CMD ["/usr/local/bin/funmail-admin"]
