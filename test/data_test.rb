# -*- encoding: utf-8 -*-
require 'test_helper'

describe GPGME::Data do
  describe :initialize do
    it "smartly creates an empty buffer if nothing passed" do
      data = GPGME::Data.new
      assert_instance_of GPGME::Data, data
      assert_respond_to data, :read
      assert_respond_to data, :write
    end

    it "doesn't create a new object if the object passed is a Data already" do
      data = GPGME::Data.new
      new_data = GPGME::Data.new(data)

      assert_equal data, new_data
    end

    it "creates a data from strings" do
      data = GPGME::Data.new("wadus")
      assert_equal "wadus", data.read
    end

    it "creates a data from a file" do
      # magic fromfile
      data = GPGME::Data.new(File.open(__FILE__))
      assert_match /magic fromfile/, data.read
    end

    it "creates a data from file descriptor" do
      # magic filedescriptor
      data = GPGME::Data.new(File.open(__FILE__).fileno)
      assert_match /magic filedescriptor/, data.read
    end

  end
end

