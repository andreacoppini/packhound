#!/bin/bash
# Builds the small ffmpeg the appliance uses for the mosaic and for live
# previews: static, with only what those need.
#
#   Mosaic stills: the H.264, HEVC and MPEG-2 decoders, scaling and the JPEG
#   encoder. It starts in a fraction of the time a distribution's ffmpeg
#   takes, which is most of the cost of a still.
#
#   Previews: the MPEG-TS demuxer, the audio decoders IPTV carries (MPEG
#   audio, AAC, AC-3, E-AC-3), deinterlacing, x264 and the AAC encoder, and
#   the HLS muxer, to turn a channel into a small stream a browser plays.
#
#   scripts/build-ffmpeg.sh <output dir>
#
# Writes <output dir>/ffmpeg and <output dir>/COPYING.GPLv2. With x264 this
# ffmpeg is GPL, like Packhound.
set -euo pipefail

VERSION=7.1.1
SHA256=733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1
X264_COMMIT=31e19f92f00c7003fa115047ce50978bc98c3a0d # the stable branch
OUT=$(realpath -m "$1")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# x264, static. Pinned by commit, which a git checkout verifies.
git -c advice.detachedHead=false clone -q --filter=blob:none --no-checkout https://code.videolan.org/videolan/x264.git "$WORK/x264"
git -C "$WORK/x264" -c advice.detachedHead=false checkout -q "$X264_COMMIT"
(cd "$WORK/x264" && ./configure --prefix="$WORK/prefix" --enable-static --enable-pic --disable-cli \
	--disable-opencl --disable-lavf --disable-swscale --disable-ffms --disable-gpac --disable-lsmash >/dev/null &&
	make -j"$(nproc)" >/dev/null && make install >/dev/null)

curl -sSfL -o "$WORK/ffmpeg.tar.xz" "https://ffmpeg.org/releases/ffmpeg-$VERSION.tar.xz"
echo "$SHA256  $WORK/ffmpeg.tar.xz" | sha256sum -c --quiet
tar -C "$WORK" -xf "$WORK/ffmpeg.tar.xz"
cd "$WORK/ffmpeg-$VERSION"
PKG_CONFIG_PATH="$WORK/prefix/lib/pkgconfig" ./configure \
	--disable-everything --disable-autodetect --disable-doc --disable-network \
	--disable-ffplay --disable-ffprobe --disable-debug --disable-shared --enable-static \
	--enable-gpl --enable-libx264 --pkg-config-flags=--static \
	--extra-cflags="-I$WORK/prefix/include" --extra-ldflags="-static -L$WORK/prefix/lib" --extra-libs="-lpthread -lm" \
	--enable-decoder=h264,hevc,mpeg2video,mpeg1video,mp2,mp3,aac,aac_latm,ac3,eac3 \
	--enable-parser=h264,hevc,mpegvideo,mpegaudio,aac,aac_latm,ac3 \
	--enable-demuxer=h264,hevc,mpegvideo,mpegts \
	--enable-encoder=mjpeg,libx264,aac \
	--enable-muxer=image2pipe,mjpeg,hls,mp4,mpegts \
	--enable-filter=scale,format,null,yadif,fps,aresample,anull,aformat \
	--enable-swscale --enable-swresample \
	--enable-protocol=pipe,file >/dev/null
make -j"$(nproc)" ffmpeg >/dev/null
mkdir -p "$OUT"
strip -o "$OUT/ffmpeg" ffmpeg
cp COPYING.GPLv2 "$OUT/"
echo "ffmpeg $VERSION with x264: $OUT/ffmpeg"
