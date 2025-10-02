python3 = find_program('python3')

# Check Python version
py_version_res = run_command(python3, ['--version'], check: true)
py_version = py_version_res.stdout().split(' ')[1]
if not py_version.version_compare('>=3.9')
  error('Python 3.9 required, got @0@'.format(py_version))
endif

has_cpp = add_languages('cpp', required: false)

cc = meson.get_compiler('c')
if get_option('warning_level').to_int() >= 3
  extra_warnings = [
    '-Wmissing-prototypes', '-Wshadow',  '-Wwrite-strings', '-Wswitch-default',
    '-Winline', '-Wstrict-prototypes', '-Wundef',
    # We have strings longer than 4095 characters
    '-Wno-overlength-strings',
    # GCC 8 requires an extra option for strict cast alignment checks, Clang
    # always warns, even on architectures without alignment requirements.
    '-Wcast-align', '-Wcast-align=strict',
  ]
  add_project_arguments(cc.get_supported_arguments(extra_warnings), language: 'c')
endif
if cc.get_argument_syntax() == 'msvc'
  # Disable some warnings to align warnings with GCC and Clang:
  add_project_arguments('-D_CRT_SECURE_NO_WARNINGS',
                        '/wd4018', # - Signed/unsigned comparison
                        '/wd4146', # - Unary minus operator applied to unsigned
                                   #   type, result still unsigned
                        '/wd4244', # - Possible loss of data in conversion
                                   #   from integer type to smaller integer type
                        '/wd4245', # - Signed/unsigned assignment
                        '/wd4267', # - Possible loss of data in conversion
                                   #   from size_t to smaller type
                        '/wd4310', # - Possible loss of data in conversion
                                   #   of constant value to smaller type
                        language: 'c')
endif
if cc.get_id() == 'msvc' and has_cpp
  cxx = meson.get_compiler('cpp')
  if cxx.get_id() == 'msvc'
    # Enable standard conformant preprocessor
    add_project_arguments(cxx.get_supported_arguments(['-Zc:preprocessor']), language: 'cpp')
  endif
endif

sources = []
headers = []
components = []

components += 'decode'
headers += files('fadec.h')
sources += files('decode.c', 'format.c')

generate_args = []
generate_args += ['--64']

tables = []
foreach component : components
  tables += custom_target('@0@_table'.format(component),
                          command: [python3, '@INPUT0@', component,
                                    '@INPUT1@', '@OUTPUT@'] + generate_args,
                          input: files('parseinstrs.py', 'instrs.txt'),
                          output: ['fadec-@0@-public.inc'.format(component),
                                   'fadec-@0@-private.inc'.format(component)],
                          install: true,
                          install_dir: [get_option('includedir'), false])
endforeach

libfadec = static_library('fadec', sources, tables, install: true)
fadec = declare_dependency(link_with: libfadec,
                           include_directories: include_directories('.'),
                           sources: tables)

foreach component : components
  test(component, executable('@0@-test'.format(component),
                             '@0@-test.c'.format(component),
                             dependencies: fadec))
  if component == 'encode2' and has_cpp
    test(component + '-cpp', executable('@0@-test-cpp'.format(component),
                                        '@0@-test.cc'.format(component),
                                        dependencies: fadec))
  endif
endforeach
