# goreleaser (dockers_v2) builds with buildx and copies the prebuilt
# static binary for the target platform. Distroless: only the binary and
# CA roots ship.
FROM gcr.io/distroless/static:nonroot
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/chancery /usr/bin/chancery
ENV CHANCERY_DATA=/data
VOLUME ["/data"]
EXPOSE 7423
ENTRYPOINT ["/usr/bin/chancery"]
CMD ["--help"]
