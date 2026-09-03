# The Docker API proxy that sits between the web UI and the daemon.
#
# python:slim rather than a distroless or scratch image built from source: this
# is a security control, and the thing that matters most about it is that
# somebody can read it, change it, and rebuild it without a toolchain. It has no
# dependencies beyond the standard library, so the image is the interpreter and
# one file.
FROM python:3.13-slim

COPY proxy.py /proxy.py

# Nothing in here writes anywhere but the socket directory, and it needs no
# privileges of its own -- it holds a connection to the daemon's socket, which
# is bind-mounted in read-only. The compose file drops the rest.
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/proxy.py"]
