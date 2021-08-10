Gem::Specification.new do |s|
  s.name = 'sequoia-ruby-ffi'
  s.version = '0.0.0'
  s.date = '2020-07-05'
  s.summary = 'Bindings for Sequoia-PGP'
  s.description =
    "This gem contains bindings for Sequoia-PGP," \
    "an OpenPGP implementation in rust."
  s.post_install_message =
    "\nBefore using these bindings you have to run\n" \
    "  $ rake install\n" \
    "to auto generate and set up needed files\n\n"
  s.authors = ['Dorle Osterode']
  s.email = 'dorle.osterode@mailbox.org'
  s.files = `git ls-files`.split
  s.license = 'MIT'

  s.add_dependency 'ffi',  '~> 1'
  s.add_development_dependency 'rake', '~> 12'
end
