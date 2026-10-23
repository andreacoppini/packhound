#!/bin/bash
# Builds the small ffmpeg the appliance uses for the mosaic: static, with only
# what turning a key picture into a JPEG needs (the H.264, HEVC and MPEG-2
# decoders, scaling and the JPEG encoder). It starts in a fraction of the
# time a distribution's ffmpeg takes, which is most of the cost of a still.
#
#   scripts/build-ffmpeg.sh <output dir>
#
# Writes <output dir>/ffmpeg and <output dir>/COPYING.LGPLv2.1. FFmpeg is
# LGPL; this build enables nothing that would make it GPL.
set -euo pipefail

VERSION=7.1.1
SHA256=733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1
OUT=$(realpath -m "$1")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

curl -sSfL -o "$WORK/ffmpeg.tar.xz" "https://ffmpeg.org/releases/ffmpeg-$VERSION.tar.xz"
echo "$SHA256  $WORK/ffmpeg.tar.xz" | sha256sum -c --quiet
tar -C "$WORK" -xf "$WORK/ffmpeg.tar.xz"
cd "$WORK/ffmpeg-$VERSION"
./configure --disable-everything --disable-autodetect --disable-doc --disable-network \
	--disable-ffplay --disable-ffprobe --disable-debug --disable-shared --enable-static \
	--extra-ldflags=-static \
	--enable-decoder=h264,hevc,mpeg2video,mpeg1video \
	--enable-parser=h264,hevc,mpegvideo \
	--enable-demuxer=h264,hevc,mpegvideo \
	--enable-encoder=mjpeg --enable-muxer=image2pipe,mjpeg \
	--enable-filter=scale,format,null --enable-swscale \
	--enable-protocol=pipe,file >/dev/null
make -j"$(nproc)" ffmpeg >/dev/null
mkdir -p "$OUT"
strip -o "$OUT/ffmpeg" ffmpeg
cp COPYING.LGPLv2.1 "$OUT/"
echo "ffmpeg $VERSION: $OUT/ffmpeg"
