#!/bin/sh -e

# Creates a minimised install of dynamorio (no duplicated files).

src="$1"
dst=$(realpath "$2")

if [ $# -ne 2 ]; then
  echo "Usage: ./minify_dyanmorio src dst" 1>&2
  exit 1
fi

if [ ! -d "$src" ]; then
  echo "Directory not found: $src" 1>&2
  exit 1
fi
if [ ! -d "$dst" ]; then
  mkdir "$dst"
fi
if [ -n "$(ls -A "$dst")" ]; then
  echo "Destination directory not empty: $dst" 1>&2
  exit 1
fi

subdirs="lib* bin* ext/lib* ext/bin*"
cd "$src"

cp License.txt $dst/License.txt

# Create all subdirectories of lib{32,64}; bin{32,64} and the ext versions of
# these in the destination.
find $subdirs -type d \
  | sort | sed -ne "s^mkdir -p $dst/p" \
  | sh -xe 2>&1

# Copy one copy of each file in those directories (identified uniquely by the
# sha1sum).
find $subdirs -type f ! -name '*.debug' -exec sha1sum '{}' + \
  | sort | uniq -w 40 | sed -ne "s[0-9a-f]\\{40\\}  \(.*\)cp \1 $dst/\1p" \
  | sh -xe 2>&1

# Determine the 'strip' program
strip=$(${CXX:-c++} -dumpmachine)-strip
if ! which "$strip" > /dev/null 2> /dev/null; then
  strip=strip
fi

# Strip any executable files.
find "$dst" -type f -name '*.a' -perm /u+w -exec "$strip" '{}' + -printf "+ $strip"' %P\n'
find "$dst" -type f -name '*.so' -perm /u+w -exec "$strip" '{}' + -printf "+ $strip"' %P\n'
find "$dst" -type f -perm /u+w -perm /u+x -exec "$strip" '{}' + -printf "+ $strip"' %P\n'

# Copy all symbolic links.
find $subdirs -type l ! -name '*.debug' \
  | sed -ne "s\(.*\)cp \1 $dst/\1p" \
  | sh -xe 2>&1

# For each non-unique file, create a symlink 
find $subdirs -type f ! -name '*.debug' -exec sha1sum '{}' + \
  | sort | uniq -D -w 40 \
  | awk '
BEGIN { FIELDWIDTHS="40 2:*" }
{
  if (hash == $1) {
    print "ln -s -T $(realpath --relative-to=$(dirname \"'"$dst"'/"$2"\") \"'"$dst"'/"file"\") '"$dst"'/"$2
  }
  else {
    hash=$1
    file=$2
  }
}' \
  | sh -xe 2>&1

cat > "$dst"/README <<EOF
This is a stripped version of $(basename "$src"). It has had unnecessary files
and debugging information removed to save space.
EOF
