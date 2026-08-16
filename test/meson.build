tests_arm64 = [
  'arm64/pass.s',
  'arm64/pass_msr.s',
  'arm64/fail.s',
]

tests_x64 = [
  'x64/pass.s',
  'x64/fail.s',
]

tests_riscv64 = [
  'riscv64/pass.s',
  'riscv64/fail.s',
]

go = find_program('go')

clang = find_program('clang', required: false)

if clang.found()
  if 'arm64' in arch
    foreach t : tests_arm64
      test('@0@'.format(t), go, args: ['run', 'runtest.go', '-arch', 'arm64', lfiv_exec, t], workdir: meson.current_source_dir(), suite: ['lfi-verify', 'arm64'], protocol: 'tap')
    endforeach
  endif

  if 'x64' in arch
    foreach t : tests_x64
      test('@0@'.format(t), go, args: ['run', 'runtest.go', '-arch', 'x64', lfiv_exec, t], workdir: meson.current_source_dir(), suite: ['lfi-verify', 'x64'], protocol: 'tap')
    endforeach
  endif

  if 'riscv64' in arch
    foreach t : tests_riscv64
      test('@0@'.format(t), go, args: ['run', 'runtest.go', '-arch', 'riscv64', lfiv_exec, t], workdir: meson.current_source_dir(), suite: ['lfi-verify', 'riscv64'], protocol: 'tap')
    endforeach
  endif
endif
