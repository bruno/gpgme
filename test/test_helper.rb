# -*- encoding: utf-8 -*-
require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/spec'
require 'mocha'
require 'gpgme'

require File.dirname(__FILE__) + "/support/resources"

# Import a key pair at the beginning to be used throughout the tests
puts "Importing keys..."
GPGME.import PUBLIC_KEY
GPGME.import PRIVATE_KEY

# Remove the tests key at the end of test execution
MiniTest::Unit.after_tests do
  GPGME::Ctx.new do |ctx|
    key = GPGME.list_keys(KEY_SHA).first
    ctx.delete_key key, true
  end
end
