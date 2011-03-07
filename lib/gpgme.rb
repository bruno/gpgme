$:.push File.expand_path("../..", __FILE__) # C extension is in the root

require 'gpgme_n'
require 'gpgme/constants'
require 'gpgme/ctx'
require 'gpgme/data'
require 'gpgme/error'
require 'gpgme/io_callbacks'
require 'gpgme/key'
require 'gpgme/key_sig'
require 'gpgme/misc'
require 'gpgme/signature'
require 'gpgme/sub_key'
require 'gpgme/user_id'
require 'gpgme/high_level'

module GPGME

  PROTOCOL_NAMES = {
    PROTOCOL_OpenPGP => :OpenPGP,
    PROTOCOL_CMS => :CMS
  }

  KEYLIST_MODE_NAMES = {
    KEYLIST_MODE_LOCAL => :local,
    KEYLIST_MODE_EXTERN => :extern,
    KEYLIST_MODE_SIGS => :sigs,
    KEYLIST_MODE_VALIDATE => :validate
  }

  VALIDITY_NAMES = {
    VALIDITY_UNKNOWN => :unknown,
    VALIDITY_UNDEFINED => :undefined,
    VALIDITY_NEVER => :never,
    VALIDITY_MARGINAL => :marginal,
    VALIDITY_FULL => :full,
    VALIDITY_ULTIMATE => :ultimate
  }
  # :startdoc:

  def error_to_exception(err)   # :nodoc:
    case GPGME::gpgme_err_code(err)
    when GPG_ERR_EOF
      EOFError.new
    when GPG_ERR_NO_ERROR
      nil
    when GPG_ERR_GENERAL
      Error::General.new(err)
    when GPG_ERR_ENOMEM
      Errno::ENOMEM.new
    when GPG_ERR_INV_VALUE
      Error::InvalidValue.new(err)
    when GPG_ERR_UNUSABLE_PUBKEY
      Error::UnusablePublicKey.new(err)
    when GPG_ERR_UNUSABLE_SECKEY
      Error::UnusableSecretKey.new(err)
    when GPG_ERR_NO_DATA
      Error::NoData.new(err)
    when GPG_ERR_CONFLICT
      Error::Conflict.new(err)
    when GPG_ERR_NOT_IMPLEMENTED
      Error::NotImplemented.new(err)
    when GPG_ERR_DECRYPT_FAILED
      Error::DecryptFailed.new(err)
    when GPG_ERR_BAD_PASSPHRASE
      Error::BadPassphrase.new(err)
    when GPG_ERR_CANCELED
      Error::Canceled.new(err)
    when GPG_ERR_INV_ENGINE
      Error::InvalidEngine.new(err)
    when GPG_ERR_AMBIGUOUS_NAME
      Error::AmbiguousName.new(err)
    when GPG_ERR_WRONG_KEY_USAGE
      Error::WrongKeyUsage.new(err)
    when GPG_ERR_CERT_REVOKED
      Error::CertificateRevoked.new(err)
    when GPG_ERR_CERT_EXPIRED
      Error::CertificateExpired.new(err)
    when GPG_ERR_NO_CRL_KNOWN
      Error::NoCRLKnown.new(err)
    when GPG_ERR_NO_POLICY_MATCH
      Error::NoPolicyMatch.new(err)
    when GPG_ERR_NO_SECKEY
      Error::NoSecretKey.new(err)
    when GPG_ERR_MISSING_CERT
      Error::MissingCertificate.new(err)
    when GPG_ERR_BAD_CERT_CHAIN
      Error::BadCertificateChain.new(err)
    when GPG_ERR_UNSUPPORTED_ALGORITHM
      Error::UnsupportedAlgorithm.new(err)
    when GPG_ERR_BAD_SIGNATURE
      Error::BadSignature.new(err)
    when GPG_ERR_NO_PUBKEY
      Error::NoPublicKey.new(err)
    else
      Error.new(err)
    end
  end
  module_function :error_to_exception
  private :error_to_exception

  class << self
    alias pubkey_algo_name gpgme_pubkey_algo_name
    alias hash_algo_name gpgme_hash_algo_name
  end

  # Verify that the engine implementing the protocol <i>proto</i> is
  # installed in the system.
  def engine_check_version(proto)
    err = GPGME::gpgme_engine_check_version(proto)
    exc = GPGME::error_to_exception(err)
    raise exc if exc
  end
  module_function :engine_check_version

  # Return a list of info structures of enabled engines.
  def engine_info
    rinfo = Array.new
    GPGME::gpgme_get_engine_info(rinfo)
    rinfo
  end
  module_function :engine_info

  # Change the default configuration of the crypto engine implementing
  # protocol <i>proto</i>.
  #
  # <i>file_name</i> is the file name of the executable program
  # implementing the protocol.
  # <i>home_dir</i> is the directory name of the configuration directory.
  def set_engine_info(proto, file_name, home_dir)
    err = GPGME::gpgme_set_engine_info(proto, file_name, home_dir)
    exc = GPGME::error_to_exception(err)
    raise exc if exc
  end
  module_function :set_engine_info

  ##
  # Begin of high level API
  class << self
    # call-seq:
    #   GPGME.decrypt(cipher, plain=nil, options=Hash.new){|signature| ...}
    #
    # <code>GPGME.decrypt</code> performs decryption.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.decrypt(<i>cipher</i>, <i>plain</i>, <i>options</i>)
    # - GPGME.decrypt(<i>cipher</i>, <i>options</i>) -> <i>plain</i>
    #
    # All arguments except <i>cipher</i> are optional.  <i>cipher</i> is
    # input, and <i>plain</i> is output.  If the last argument is a
    # Hash, options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def decrypt(cipher, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      plain = args[0]

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        cipher_data = input_data(cipher)
        plain_data = output_data(plain)
        begin
          ctx.decrypt_verify(cipher_data, plain_data)
        rescue GPGME::Error::UnsupportedAlgorithm => exc
          exc.algorithm = ctx.decrypt_result.unsupported_algorithm
          raise exc
        rescue GPGME::Error::WrongKeyUsage => exc
          exc.key_usage = ctx.decrypt_result.wrong_key_usage
          raise exc
        end

        verify_result = ctx.verify_result
        if verify_result && block_given?
          verify_result.signatures.each do |signature|
            yield signature
          end
        end

        unless plain
          plain_data.seek(0, IO::SEEK_SET)
          plain_data.read
        end
      end
    end

    # call-seq:
    #   GPGME.verify(sig, signed_text=nil, plain=nil, options=Hash.new){|signature| ...}
    #
    # <code>GPGME.verify</code> verifies a signature.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.verify(<i>sig</i>, <i>signed_text</i>, <i>plain</i>, <i>options</i>)
    # - GPGME.verify(<i>sig</i>, <i>signed_text</i>, <i>options</i>) -> <i>plain</i>
    #
    # All arguments except <i>sig</i> are optional.  <i>sig</i> and
    # <i>signed_text</i> are input.  <i>plain</i> is output.  If the last
    # argument is a Hash, options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # If <i>sig</i> is a detached signature, then the signed text should
    # be provided in <i>signed_text</i> and <i>plain</i> should be
    # <tt>nil</tt>.  Otherwise, if <i>sig</i> is a normal (or cleartext)
    # signature, <i>signed_text</i> should be <tt>nil</tt>.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def verify(sig, *args_options) # :yields: signature
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
      args, options = split_args(args_options)
      signed_text, plain = args

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        sig_data = input_data(sig)
        if signed_text
          signed_text_data = input_data(signed_text)
          plain_data = nil
        else
          signed_text_data = nil
          plain_data = output_data(plain)
        end
        ctx.verify(sig_data, signed_text_data, plain_data)
        ctx.verify_result.signatures.each do |signature|
          yield signature
        end
        if !signed_text && !plain
          plain_data.seek(0, IO::SEEK_SET)
          plain_data.read
        end
      end
    end

    # call-seq:
    #   GPGME.sign(plain, sig=nil, options=Hash.new)
    #
    # <code>GPGME.sign</code> creates a signature of the plaintext.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.sign(<i>plain</i>, <i>sig</i>, <i>options</i>)
    # - GPGME.sign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
    #
    # All arguments except <i>plain</i> are optional.  <i>plain</i> is
    # input and <i>sig</i> is output.  If the last argument is a Hash,
    # options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    # - <tt>:mode</tt> Desired type of a signature.  Either
    #   <tt>GPGME::SIG_MODE_NORMAL</tt> for a normal signature,
    #   <tt>GPGME::SIG_MODE_DETACH</tt> for a detached signature, or
    #   <tt>GPGME::SIG_MODE_CLEAR</tt> for a cleartext signature.
    #
    def sign(plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      sig = args[0]

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.add_signer(*resolve_keys(options[:signers], true, [:sign])) if options[:signers]
        mode = options[:mode] || GPGME::SIG_MODE_NORMAL
        plain_data = input_data(plain)
        sig_data = output_data(sig)
        begin
          ctx.sign(plain_data, sig_data, mode)
        rescue GPGME::Error::UnusableSecretKey => exc
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end

        unless sig
          sig_data.seek(0, IO::SEEK_SET)
          sig_data.read
        end
      end
    end

    # call-seq:
    #   GPGME.clearsign(plain, sig=nil, options=Hash.new)
    #
    # <code>GPGME.clearsign</code> creates a cleartext signature of the plaintext.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.clearsign(<i>plain</i>, <i>sig</i>, <i>options</i>)
    # - GPGME.clearsign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
    #
    # All arguments except <i>plain</i> are optional.  <i>plain</i> is
    # input and <i>sig</i> is output.  If the last argument is a Hash,
    # options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    #
    def clearsign(plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      args.push(options.merge({:mode => GPGME::SIG_MODE_CLEAR}))
      GPGME.sign(plain, *args)
    end

    # call-seq:
    #   GPGME.detach_sign(plain, sig=nil, options=Hash.new)
    #
    # <code>GPGME.detach_sign</code> creates a detached signature of the plaintext.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.detach_sign(<i>plain</i>, <i>sig</i>, <i>options</i>)
    # - GPGME.detach_sign(<i>plain</i>, <i>options</i>) -> <i>sig</i>
    #
    # All arguments except <i>plain</i> are optional.  <i>plain</i> is
    # input and <i>sig</i> is output.  If the last argument is a Hash,
    # options will be read from it.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    #
    def detach_sign(plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      args.push(options.merge({:mode => GPGME::SIG_MODE_DETACH}))
      GPGME.sign(plain, *args)
    end

    # call-seq:
    #   GPGME.encrypt(recipients, plain, cipher=nil, options=Hash.new)
    #
    # <code>GPGME.encrypt</code> performs encryption.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.encrypt(<i>recipients</i>, <i>plain</i>, <i>cipher</i>, <i>options</i>)
    # - GPGME.encrypt(<i>recipients</i>, <i>plain</i>, <i>options</i>) -> <i>cipher</i>
    #
    # All arguments except <i>recipients</i> and <i>plain</i> are
    # optional.  <i>plain</i> is input and <i>cipher</i> is output.  If
    # the last argument is a Hash, options will be read from it.
    #
    # The recipients are specified by an array whose elements are a string
    # or a GPGME::Key object.  If <i>recipients</i> is <tt>nil</tt>, it
    # performs symmetric encryption.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code> except for
    #
    # - <tt>:sign</tt> If <tt>true</tt>, it performs a combined sign and
    #   encrypt operation.
    # - <tt>:signers</tt> Signing keys.  If specified, it is an array
    #   whose elements are a GPGME::Key object or a string.
    # - <tt>:always_trust</tt> Setting this to <tt>true</tt> specifies all
    #   the recipients should be trusted.
    #
    def encrypt(recipients, plain, *args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
      args, options = split_args(args_options)
      cipher = args[0]
      recipient_keys = recipients ? resolve_keys(recipients, false, [:encrypt]) : nil

      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        plain_data = input_data(plain)
        cipher_data = output_data(cipher)
        begin
          flags = 0
          if options[:always_trust]
            flags |= GPGME::ENCRYPT_ALWAYS_TRUST
          end
          if options[:sign]
            if options[:signers]
              ctx.add_signer(*resolve_keys(options[:signers], true, [:sign]))
            end
            ctx.encrypt_sign(recipient_keys, plain_data, cipher_data, flags)
          else
            ctx.encrypt(recipient_keys, plain_data, cipher_data, flags)
          end
        rescue GPGME::Error::UnusablePublicKey => exc
          exc.keys = ctx.encrypt_result.invalid_recipients
          raise exc
        rescue GPGME::Error::UnusableSecretKey => exc
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end

        unless cipher
          cipher_data.seek(0, IO::SEEK_SET)
          cipher_data.read
        end
      end
    end

    # call-seq:
    #   GPGME.list_keys(pattern=nil, secret_only=false, options=Hash.new){|key| ...}
    #
    # <code>GPGME.list_keys</code> iterates over the key ring.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.list_keys(<i>pattern</i>, <i>secret_only</i>, <i>options</i>)
    #
    # All arguments are optional.  If the last argument is a Hash, options
    # will be read from it.
    #
    # <i>pattern</i> is a string or <tt>nil</tt>.  If <i>pattern</i> is
    # <tt>nil</tt>, all available keys are returned.  If
    # <i>secret_only</i> is <tt>true</tt>, the only secret keys are
    # returned.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def list_keys(*args_options) # :yields: key
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 3
      args, options = split_args(args_options)
      pattern, secret_only = args
      check_version(options)
      GPGME::Ctx.new do |ctx|
        if block_given?
          ctx.each_key(pattern, secret_only || false) do |key|
            yield key
          end
        else
          ctx.keys(pattern, secret_only || false)
        end
      end
    end

    # call-seq:
    #   GPGME.export(pattern)
    #
    # <code>GPGME.export</code> extracts public keys from the key ring.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.export(<i>pattern</i>, <i>options</i>) -> <i>keydata</i>
    # - GPGME.export(<i>pattern</i>, <i>keydata</i>, <i>options</i>)
    #
    # All arguments are optional.  If the last argument is a Hash, options
    # will be read from it.
    #
    # <i>pattern</i> is a string or <tt>nil</tt>.  If <i>pattern</i> is
    # <tt>nil</tt>, all available public keys are returned.
    # <i>keydata</i> is output.
    #
    # An output argument is specified by an IO like object (which responds
    # to <code>write</code>) or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def export(*args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      pattern, key = args[0]
      key_data = output_data(key)
      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.export_keys(pattern, key_data)

        unless key
          key_data.seek(0, IO::SEEK_SET)
          key_data.read
        end
      end
    end

    # call-seq:
    #   GPGME.import(keydata)
    #
    # <code>GPGME.import</code> adds the keys to the key ring.
    #
    # The arguments should be specified as follows.
    #
    # - GPGME.import(<i>keydata</i>, <i>options</i>)
    #
    # All arguments are optional.  If the last argument is a Hash, options
    # will be read from it.
    #
    # <i>keydata</i> is input.
    #
    # An input argument is specified by an IO like object (which responds
    # to <code>read</code>), a string, or a GPGME::Data object.
    #
    # <i>options</i> are same as <code>GPGME::Ctx.new()</code>.
    #
    def import(*args_options)
      raise ArgumentError, 'wrong number of arguments' if args_options.length > 2
      args, options = split_args(args_options)
      key = args[0]
      key_data = input_data(key)
      check_version(options)
      GPGME::Ctx.new(options) do |ctx|
        ctx.import_keys(key_data)
        ctx.import_result
      end
    end
  end

  # :stopdoc:
  private

  def split_args(args_options)
    if args_options.length > 0 and args_options[-1].respond_to? :to_hash
      args = args_options[0 ... -1]
      options = args_options[-1].to_hash
    else
      args = args_options
      options = Hash.new
    end
    [args, options]
  end
  module_function :split_args

  def check_version(options = nil)
    version = nil
    if options.kind_of?(String)
      version = options
    elsif options.include?(:version)
      version = options[:version]
    end
    unless GPGME::gpgme_check_version(version)
      raise Error::InvalidVersion.new
    end
  end
  module_function :check_version

  def resolve_keys(keys_or_names, secret_only, purposes = Array.new)
    keys = Array.new
    keys_or_names.each do |key_or_name|
      if key_or_name.kind_of? Key
        keys << key_or_name
      elsif key_or_name.kind_of? String
        GPGME::Ctx.new do |ctx|
          key = ctx.keys(key_or_name, secret_only).find {|k|
            k.usable_for?(purposes)
          }
          keys << key if key
        end
      end
    end
    keys
  end
  module_function :resolve_keys

  def input_data(input)
    if input.kind_of? GPGME::Data
      input
    elsif input.respond_to? :to_str
      GPGME::Data.from_str(input.to_str)
    elsif input.respond_to? :read
      GPGME::Data.from_callbacks(IOCallbacks.new(input))
    else
      raise ArgumentError, input.inspect
    end
  end
  module_function :input_data

  def output_data(output)
    if output.kind_of? GPGME::Data
      output
    elsif output.respond_to? :write
      GPGME::Data.from_callbacks(IOCallbacks.new(output))
    elsif !output
      GPGME::Data.empty
    else
      raise ArgumentError, output.inspect
    end
  end
  module_function :output_data

end
