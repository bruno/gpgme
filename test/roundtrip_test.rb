# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME do
  it "does the roundtrip encrypting" do
    encrypted = GPGME.encrypt [KEY[:sha]], TEXT[:plain], :always_trust => true
    assert_equal TEXT[:plain], GPGME.decrypt(encrypted)
  end

  it "does so even with armored encrypted stuff" do
    encrypted = GPGME.encrypt [KEY[:sha]], TEXT[:plain],
      :always_trust => true, :armor => true
    assert_equal TEXT[:plain], GPGME.decrypt(encrypted)
  end

  #   encrypted = GPGME.encrypt [KEY[:sha]], TEXT[:plain],
  #     :always_trust => true, :sign => true
  it "can also sign at the same time"

  describe :encrypt do
    it "should raise an error if the recipients aren't trusted" do
      assert_raises GPGME::Error::General do
        GPGME.encrypt [KEY[:sha]], TEXT[:plain]
      end
    end
  end
end
