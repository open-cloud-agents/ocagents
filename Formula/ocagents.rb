# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary (Model A)
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-darwin-arm64.tar.gz"
    sha256 "b6d201c8af54849eb93bbdb55c49ff8c816fcc44e7c9c807c2aa91a78f6b9c66"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-darwin-amd64.tar.gz"
    sha256 "afd5b9c15a3f4bfffab822df4459bb03c88aca7c3be6fa0126d1f7c391f20ece"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-linux-amd64.tar.gz"
    sha256 "efa5178403b2a3c82c75836e354269bef5f8d40b352cd0750b116f4e35944cd1"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-linux-arm64.tar.gz"
    sha256 "c3446c55c0f81c15784eab94731fb115c07cc012faac443903b77715c4b94bec"
  end

  def install
    bin.install "ocagents"
    bin.install_symlink bin/"ocagents" => "oca"
  end

  test do
    assert_match "Open Cloud Agents", shell_output("#{bin}/ocagents info")
    assert_match "Principal Cloud Architect", shell_output("#{bin}/ocagents list")
  end
end
