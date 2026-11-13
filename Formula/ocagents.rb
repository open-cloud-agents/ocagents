# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "2.0.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.0/ocagents-darwin-arm64.tar.gz"
    sha256 "f7f15d04aa5a0e0e5904442bbb22320fdca99b806d904753d0d14bdfbd8d9830"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.0/ocagents-darwin-amd64.tar.gz"
    sha256 "f7f15d04aa5a0e0e5904442bbb22320fdca99b806d904753d0d14bdfbd8d9830"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.0/ocagents-linux-amd64.tar.gz"
    sha256 "a2ad2cbc4c8899b3b99f8cfa5e299d08f49de06d5e02e97b6e8668255d7e4084"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.0/ocagents-linux-arm64.tar.gz"
    sha256 "6dd8ba8a3a21afa1a39e7bc4e11a69a33f7906c53ac6cc2e2fe150d5d3171a35"
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
