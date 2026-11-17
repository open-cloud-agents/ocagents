# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "2.0.2"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.2/ocagents-darwin-arm64.tar.gz"
    sha256 "03f34f1a7deb2d8a5fc891153f76d000cc2e205e8d52e2caa203deb7cf6c292c"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.2/ocagents-darwin-amd64.tar.gz"
    sha256 "0d1c2070afee669718a34a5e45ddda16236eb3f0257c143c061538df33bbc494"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.2/ocagents-linux-amd64.tar.gz"
    sha256 "1e323c4e325bd2154a1b8afc27241fc9a53fd1ff2ccd274ac7325865a32cbc85"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.2/ocagents-linux-arm64.tar.gz"
    sha256 "3151ef13b25c8ff735f6f306fc1759dd7345f00990f83a4baf3b37f9631d79a4"
  end

  depends_on "python@3.11" => :recommended
  depends_on "shellcheck" => :recommended
  depends_on "ruff" => :recommended
  depends_on "trivy" => :optional
  depends_on "checkov" => :optional

  def install
    if File.exist?("ocagents") && File.directory?("_internal")
      libexec.install Dir["*"]
      bin.install_symlink libexec/"ocagents" => "ocagents"
    elsif File.exist?("ocagents") && !File.directory?("ocagents")
      bin.install "ocagents"
    elsif File.exist?("dist/ocagents")
      bin.install "dist/ocagents" => "ocagents"
    elsif File.exist?("bin/ocagents")
      libexec.install Dir["*"]
      (bin/"ocagents").write <<~EOS
        #!/usr/bin/env bash
        export OCAGENTS_HOME="#{libexec}"
        exec "#{libexec}/bin/ocagents" "$@"
      EOS
    else
      libexec.install Dir["*"]
      bin.install_symlink libexec/"ocagents" => "ocagents"
    end
    bin.install_symlink bin/"ocagents" => "oca"
  end

  test do
    assert_match "Open Cloud Agents", shell_output("#{bin}/ocagents info")
    assert_match "Principal Cloud Architect", shell_output("#{bin}/ocagents list")
    assert_match "Deterministic Pre-Flight Gatekeeper", shell_output("#{bin}/ocagents preflight --help")
    assert_match "Open Cloud Agents", shell_output("#{bin}/oca version")
  end
end
