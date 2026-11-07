# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "1.5.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.5.0/ocagents-darwin-arm64.tar.gz"
    sha256 "3067cef5a79d8b5f6f8914c19ef913e818b47b1e0201611f9bcc7fb615ae6ddc"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.5.0/ocagents-darwin-amd64.tar.gz"
    sha256 "3067cef5a79d8b5f6f8914c19ef913e818b47b1e0201611f9bcc7fb615ae6ddc"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.5.0/ocagents-linux-amd64.tar.gz"
    sha256 "c20deba4f42a02ffd22075264c8b096120b200ec8ecc4d1173d7c0513a3074e9"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.5.0/ocagents-linux-arm64.tar.gz"
    sha256 "7e35d0e2bbc1f7cdba08147ce622acc1aea26af3c2823cd8bcd61cad0bcb5227"
  end

  depends_on "python@3.11" => :recommended
  depends_on "shellcheck" => :recommended
  depends_on "trivy" => :optional
  depends_on "checkov" => :optional

  def install
    if File.exist?("ocagents") && !File.directory?("ocagents")
      bin.install "ocagents"
    elsif File.exist?("dist/ocagents")
      bin.install "dist/ocagents" => "ocagents"
    else
      libexec.install Dir["*"]
      (bin/"ocagents").write <<~EOS
        #!/usr/bin/env bash
        export OCAGENTS_HOME="#{libexec}"
        exec "#{libexec}/bin/ocagents" "$@"
      EOS
    end
    bin.install_symlink bin/"ocagents" => "oca"
  end

  test do
    assert_match "Open Cloud Agents", shell_output("#{bin}/ocagents info")
    assert_match "Principal Cloud Architect", shell_output("#{bin}/ocagents list")
    assert_match "Deterministic Pre-Flight Gatekeeper", shell_output("#{bin}/ocagents preflight --help")
    assert_match "findings", shell_output("#{bin}/ocagents findings --help")
  end
end
