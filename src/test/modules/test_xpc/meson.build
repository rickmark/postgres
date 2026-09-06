# Copyright (c) 2022-2026, PostgreSQL Global Development Group

if host_system != 'darwin'
  subdir_done()
endif

test_xpc_sources = files(
  'test_xpc.c',
)

test_xpc = executable('test_xpc',
  test_xpc_sources,
  dependencies: [frontend_code, libpq, darwin_frameworks],
  kwargs: default_bin_args + {
    'install': false,
  },
)
testprep_targets += test_xpc

tests += {
  'name': 'test_xpc',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_xpc.pl',
    ],
    'deps': [test_xpc],
  },
}
