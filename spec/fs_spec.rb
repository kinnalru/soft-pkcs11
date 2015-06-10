#!/usr/bin/env ruby
require 'rspec'

RSpec.configure do |config|
  config.color = true
  config.tty = true
  config.formatter = :documentation
end


shared_context "Initialize folder", need_values: 'dirs' do
  before(:all) do
    %x(mkdir -p /tmp/st/)
    @tmpdir=%x(mktemp -d -p /tmp/st).strip
    @keydir="#{@tmpdir}/keys"
    @keydir2="#{@tmpdir}/keys/tmp"
    %x(mkdir -p #{@keydir})
    %x(mkdir -p #{@keydir2})
    @cfgfile="#{@tmpdir}/.soft-token.rc"
    @module="#{ENV['MODULE']}/libsoft-pkcs.so"

    ENV['SOFTPKCS11RC'] = @cfgfile

    puts "export SOFTPKCS11RC=\"#{@cfgfile}\""
  end

  before(:each) do
  end

  after(:all) do
    if @tmpdir['/tmp/st'] && File.exists?(@tmpdir)
      # FileUtils.rm_rf(@tmpdir)
    end
  end

end

shared_examples "simple keypair" do
  it "should deal with simple keypair" do
    output = %x(ssh-keygen -f #{@keydir}/test -N "")
    result = ($? == 0)
    expect(result).to eq true

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 13
  end

  context "should read" do

    it "SSH public key" do
      sshpub = %x(pkcs11-tool --module #{@module} -l -p 123123123 -r -y pubkey -a "SSH test.pub")
      result = ($? == 0)
      expect(result).to eq true
      expect(File.read("#{@keydir}/test.pub").strip).to eq sshpub.strip
    end

    it "SSH private key" do
      sshpriv = %x(pkcs11-tool --module #{@module} -l -p 123123123 -r -y privkey -a "test")
      result = ($? == 0)
      expect(result).to eq true
      expect(File.read("#{@keydir}/test").strip).to eq sshpriv.strip
    end

    it "SSH public key in openssl format" do
      rsapub = %x(pkcs11-tool --module #{@module} -l -p 123123123 -r -y pubkey -a "test.pub")
      result = ($? == 0)
      rsapub2 = %x(ssh-keygen -f #{@keydir}/test.pub -e -m PKCS8)
      result2 = ($? == 0)

      expect(result).to eq true
      expect(result2).to eq true
      expect(rsapub.strip).to eq rsapub2.strip
    end

  end

end

shared_examples "store keypair" do
  it "generate another keypair" do
    output = %x(ssh-keygen -f #{@keydir2}/newkey -N "")
    result = ($? == 0)
    expect(result).to eq true

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123 | grep newkey)
    result = ($? == 0)
    expect(result).to eq false
    expect(output.strip.split("\n").count).to eq 0
  end


  context "add keys to container" do
    it "private key" do
      output = %x(pkcs11-tool  --module #{@module} -l -p 123123123 -w #{@keydir2}/newkey --label newkey.key --type data)
      result = ($? == 0)

      output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123 | grep newkey)
      result = ($? == 0)
      expect(result).to eq true
      expect(output.strip.split("\n").count).to eq 1

    end

    it "public key" do
      output = %x(pkcs11-tool  --module #{@module} -l -p 123123123 -w #{@keydir2}/newkey.pub --label newkey.pub --type data)
      result = ($? == 0)

      output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123 | grep newkey)
      result = ($? == 0)
      expect(result).to eq true
      expect(output.strip.split("\n").count).to eq 3
    end


    it "compare keys" do
      output = %x(pkcs11-tool  --module #{@module} -l -p 123123123 -r --label newkey.key -y privkey)
      result = ($? == 0)
      expect(output.strip).to eq File.read("#{@keydir2}/newkey").strip

      output = %x(pkcs11-tool  --module #{@module} -l -p 123123123 -r --label "SSH newkey.pub" -y pubkey)
      result = ($? == 0)
      expect(output.strip).to eq File.read("#{@keydir2}/newkey.pub").strip
    end

    it "sign data with module and openssl" do
      output = %x(echo "Data to SIGN" | pkcs11-tool --module #{@module} -l -p 123123123 -m RSA-PKCS -s -a newkey.key -o #{@keydir2}/token_sign)
      result = ($? == 0)
      expect(result).to eq true

      output = %x(echo "Data to SIGN" | openssl rsautl -sign -inkey #{@keydir2}/newkey -out #{@keydir2}/openssl_sign)
      result = ($? == 0)
      expect(result).to eq true

      expect(File.read("#{@keydir2}/token_sign")).to eq File.read("#{@keydir2}/openssl_sign")

      output = %x(openssl rsautl -verify -in #{@keydir2}/token_sign -inkey #{@keydir2}/newkey -raw -hexdump)
      result = ($? == 0)
      expect(result).to eq true
    end
  end


end



describe "local FS driver", need_values: 'dirs' do

  it "must list empty keys folder" do
      
config = %{
[local fs for test]
driver=fs
path=#{@keydir}
}.strip
      
    File.write(@cfgfile, config)
    expect(File.read(@cfgfile).strip).to eq config

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 0
    
  end

  include_examples "simple keypair"
  include_examples "store keypair"
  
end


describe "local crypto driver", need_values: 'dirs' do

  it "must list empty keys folder" do
      
config = %{
[local fs for test]
driver=fs
path=#{@keydir}

[openssl encryption]
driver=crypt
decrypt=/usr/bin/openssl enc -d -base64 -aes-256-cbc -k '%PIN%'
encrypt=/usr/bin/openssl enc -base64 -aes-256-cbc -k '%PIN%'
}.strip
      
    File.write(@cfgfile, config)
    expect(File.read(@cfgfile).strip).to eq config

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 0
    
  end

  include_examples "store keypair"
  
end