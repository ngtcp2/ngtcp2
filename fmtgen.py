#!/usr/bin/env python3

N = 40

for i in range(0, N):
    args = []
    for j in range(0, i + 1):
        args.append(f'_{j + 1}')

print(
    f'#define NGTCP2_FMT_SELECT_WRITE_PACK({', '.join(args)}, PACK, ...) PACK')

packs = reversed(['NGTCP2_FMT_WRITE_PACK' + s for s in args])

print(rf'''
#define ngtcp2_fmt_format(BUF, PNWRITE, ...)                                   \
  do {{                                                                        \
    char *fmt_destp = (char *)(BUF);                                           \
    NGTCP2_FMT_SELECT_WRITE_PACK(                                              \
      __VA_ARGS__, {', '.join(packs)})(fmt_destp, __VA_ARGS__);                \
    *fmt_destp = '\0';                                                         \
    *(PNWRITE) = (size_t)(fmt_destp - (char *)(BUF));                          \
  }} while (0)
''')

for i in range(0, N):
    args = []
    for j in range(0, i + 1):
        args.append(f'_{j + 1}')

    print(f'#define NGTCP2_FMT_WRITE_PACK_{i + 1}(DEST, {', '.join(args)}) \\')

    for j in range(0, i):
        print(f'(DEST) = NGTCP2_FMT_WRITE_TYPE((DEST), (_{j + 1})); \\')

    print(f'(DEST) = NGTCP2_FMT_WRITE_TYPE((DEST), (_{i + 1}))')
