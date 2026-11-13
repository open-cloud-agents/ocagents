# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "2.0.1"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.1/ocagents-darwin-arm64.tar.gz"
    sha256 "d5791123df4eda8db9e7e5981a256250ab64ce1abc52db86f87f844926fff359"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.1/ocagents-darwin-amd64.tar.gz"
    sha256 "2b21b524816699ef980c41763b8a089c9d070e666a97bf61c559ef4b123a1690"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.1/ocagents-linux-amd64.tar.gz"
    sha256 "89dfe042ce93129b1582e08e22a730be93b33288afa683b518068cae20e6598f"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.0.1/ocagents-linux-arm64.tar.gz"
    sha256 "b0d8ccaa32ee0102afb00030c818c93dbc92c76e8f291d801c1ac154f4d0b364"
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
