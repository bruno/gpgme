# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Key do
  describe :find do
    it "should return all by default" do
      keys = GPGME::Key.find :secret
      assert_instance_of GPGME::Key, keys.first
      assert 0 < keys.size
    end

    it "returns an array even if you pass only one descriptor" do
      keys_one   = GPGME::Key.find(:secret, KEY[:sha]).map{|key| key.subkeys.map(&:keyid)}
      keys_array = GPGME::Key.find(:secret, [KEY[:sha]]).map{|key| key.subkeys.map(&:keyid)}
      assert_equal keys_one, keys_array
    end

    it "returns only secret keys if told to do so" do
      keys = GPGME::Key.find :secret
      assert keys.all?(&:secret?)
    end

    it "returns only public keys if told to do so" do
      keys = GPGME::Key.find :public
      assert keys.none?(&:secret?)
    end

    it "filters by capabilities" do
      GPGME::Key.any_instance.stubs(:usable_for?).returns(false)
      keys = GPGME::Key.find :public, "", :wadusing
      assert keys.empty?
    end
  end
end

