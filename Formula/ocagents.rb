# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary (Model A)
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-darwin-arm64.tar.gz"
    sha256 "3067cef5a79d8b5f6f8914c19ef913e818b47b1e0201611f9bcc7fb615ae6ddc"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-darwin-amd64.tar.gz"
    sha256 "3067cef5a79d8b5f6f8914c19ef913e818b47b1e0201611f9bcc7fb615ae6ddc"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-linux-amd64.tar.gz"
    sha256 "c20deba4f42a02ffd22075264c8b096120b200ec8ecc4d1173d7c0513a3074e9"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.3.1/ocagents-linux-arm64.tar.gz"
    sha256 "7e35d0e2bbc1f7cdba08147ce622acc1aea26af3c2823cd8bcd61cad0bcb5227"
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
