#!/bin/sh
# Kiểm tra dòng đầu commit message theo Conventional Commits.
# Được hook commit-msg của Lefthook gọi: sh scripts/check-commit-msg.sh <file-commit-message>
# $1 là đường dẫn file chứa commit message do Git truyền vào hook.
#
# Tách ra file riêng (thay vì viết thẳng trong lefthook.yml) vì trên Windows,
# Lefthook chạy `sh -c "<script>"` và các dấu " trong script làm vỡ cách tách tham số.

msg=$(head -n1 "$1")

# Bỏ qua commit do Git tự sinh
case "$msg" in
  Merge\ *|Revert\ *|fixup!\ *|squash!\ *) exit 0 ;;
esac

pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9-]+\))?!?: .+$'

if ! printf '%s\n' "$msg" | grep -Eq "$pattern"; then
  echo "Commit message không đúng Conventional Commits:"
  echo "  $msg"
  echo "Ví dụ hợp lệ: feat(iam): thêm API mời người dùng"
  exit 1
fi
