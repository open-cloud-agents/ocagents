# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "1.6.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.6.0/ocagents-darwin-arm64.tar.gz"
    sha256 "c8899f14d616913b8cccf7daa4d89ee92440b612ca28c8eb8b119d2e7b7ab780"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.6.0/ocagents-darwin-amd64.tar.gz"
    sha256 "c8899f14d616913b8cccf7daa4d89ee92440b612ca28c8eb8b119d2e7b7ab780"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.6.0/ocagents-linux-amd64.tar.gz"
    sha256 "edd1455de999a8ba9a96cfd7b811708a2d6d89ac0745f8a89c89e07f1496f314"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v1.6.0/ocagents-linux-arm64.tar.gz"
    sha256 "596454d356c13247a75b58d07aabb96642ef5eed5a820660679bae89798aa83e"
  end

  depends_on "python@3.11" => :recommended
  depends_on "shellcheck" => :recommended
  depends_on "ruff" => :recommended
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
    assert_match "Open Cloud Agents", shell_output("#{bin}/oca version")
  end
end
