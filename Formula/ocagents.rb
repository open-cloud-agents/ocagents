# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary (Model A)
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.2/ocagents-darwin-arm64.tar.gz"
    sha256 "d85c3351674d904a020e95abc996277dc3f8cb9e4df3a7274dd2f73619873cfe"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.2/ocagents-darwin-amd64.tar.gz"
    sha256 "d85c3351674d904a020e95abc996277dc3f8cb9e4df3a7274dd2f73619873cfe"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.2/ocagents-linux-amd64.tar.gz"
    sha256 "577a954d35fb23ecff3d78dc1a98e4a9a9a165810a7740f7205acfa83d6aecc3"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.2/ocagents-linux-arm64.tar.gz"
    sha256 "8b96802de1cd69d819c182afa59f7c587d3a5775163890296297dea93fd16e1a"
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
