require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'
require 'yard'


desc "Re-compile the extensions"
task :compile do
  FileUtils.rm('gpgme_n.bundle')
  FileUtils.rm('gpgme_n.o')
  FileUtils.rm('Makefile')

  system "ruby extconf.rb"
  system "make"
end

task :default => [:test]

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
end
Rake::Task['test'].comment = "Run all tests"

YARD::Rake::YardocTask.new
