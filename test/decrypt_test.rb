# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME do
  describe :decrypt do
    it "decrypts encrypted stuff" do
      assert_equal TEXT[:plain], GPGME.decrypt(TEXT[:encrypted]).read
    end

    it "will not get into the signatures block if there's none" do
      GPGME.decrypt(TEXT[:encrypted]) do |signature|
        flunk "If I'm here means there was some signature"
      end
      pass
    end

    it "will get signature elements if the encrypted thing was signed" do
      GPGME.decrypt(TEXT[:signed]) do |signature|
        assert_instance_of GPGME::Signature, signature
      end
    end

    it "writes to the output if passed" do
      buffer = GPGME::Data.new
      GPGME.decrypt(TEXT[:encrypted], :output => buffer)
      assert_equal TEXT[:plain], buffer.read
    end

    # TODO find ways to test this
    # it "raises UnsupportedAlgorithm"
    # it "raises WrongKeyUsage"

    # TODO fails for some reason
    # it "raises DecryptFailed when the decrypting key isn't available" do
    #   remove_keys

    #   assert_raises GPGME::Error::DecryptFailed do
    #     GPGME.decrypt(TEXT[:encrypted])
    #   end

    #   import_keys
    # end
  end
end

