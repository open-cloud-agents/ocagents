# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "2.2.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.0/ocagents-darwin-arm64.tar.gz"
    sha256 "b491ba03f910f49d91eaf05a9679f03d1973ae34d1661b0fb7ea6577c184b93e"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.0/ocagents-darwin-amd64.tar.gz"
    sha256 "dfe1367e2a68e0270cb1631023a121cfcb46f5752a3503c2f62aca4e16156d77"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.0/ocagents-linux-amd64.tar.gz"
    sha256 "d1b5f6f4aac262d68ea5e22b0614836d53d7ac7debb2ad85da48d2cc8e6a2366"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.0/ocagents-linux-arm64.tar.gz"
    sha256 "29ef02087ea84675a4871845914077bf66d9b8bd1bc8a05d2b068e699e7172aa"
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
