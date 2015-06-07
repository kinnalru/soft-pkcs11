#!/usr/bin/env ruby
require 'rspec'

RSpec.configure do |config|
  config.color = true
  config.tty = true
  config.formatter = :documentation
end


describe "Testing FS driver with pkcs11-tool" do
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

  it "empty keys folder" do
      
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

  it "generate simple keypair" do
    output = %x(ssh-keygen -f #{@keydir}/test -N "")
    result = ($? == 0)
    expect(result).to eq true

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 13
  end

  it "read SSH public key" do
    sshpub = %x(pkcs11-tool --module #{@module} -l -p 123123123 -r -y pubkey -a "SSH test.pub")
    result = ($? == 0)
    expect(result).to eq true
    expect(File.read("#{@keydir}/test.pub").strip).to eq sshpub.strip
  end

  it "read SSH private key" do
    sshpriv = %x(pkcs11-tool --module #{@module} -l -p 123123123 -r -y privkey -a "test")
    result = ($? == 0)
    expect(result).to eq true
    expect(File.read("#{@keydir}/test").strip).to eq sshpriv.strip
  end

  it "read SSH public key in openssl format" do
    rsapub = %x(pkcs11-tool --module #{@module} -l -p 123123123 -r -y pubkey -a "test.pub")
    result = ($? == 0)
    rsapub2 = %x(ssh-keygen -f #{@keydir}/test.pub -e -m PKCS8)
    result2 = ($? == 0)

    expect(result).to eq true
    expect(result2).to eq true
    expect(rsapub.strip).to eq rsapub2.strip
  end

  it "generate another keypair" do
    output = %x(ssh-keygen -f #{@keydir2}/newkey -N "")
    result = ($? == 0)
    expect(result).to eq true

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 13
  end


  it "add keys to container" do
    output = %x(pkcs11-tool  --module #{@module} -l -p 123123123 -w #{@keydir2}/newkey --label newkey.key --type data)
    result = ($? == 0)

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 18


    output = %x(pkcs11-tool  --module #{@module} -l -p 123123123 -w #{@keydir2}/newkey.pub --label newkey.pub --type data)
    result = ($? == 0)

    output = %x(pkcs11-tool --module #{@module} -O -l -p 123123123)
    result = ($? == 0)
    expect(result).to eq true
    expect(output.strip.split("\n").count).to eq 26
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


