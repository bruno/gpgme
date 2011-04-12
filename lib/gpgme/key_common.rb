module GPGME
  module KeyCommon
    def trust
      return :revoked if @revoked == 1
      return :expired if @expired == 1
      return :disabled if @disabled == 1
      return :invalid if @invalid == 1
    end

    def capability
      caps = Array.new
      caps << :encrypt if @can_encrypt
      caps << :sign if @can_sign
      caps << :certify if @can_certify
      caps << :authenticate if @can_authenticate
      caps
    end

    def usable_for?(purposes)
      unless purposes.kind_of? Array
        purposes = [purposes]
      end
      return false if [:revoked, :expired, :disabled, :invalid].include? trust
      return (purposes - capability).empty?
    end

    def secret?
      @secret == 1
    end
  end
end
