# Homebrew Formula for Open Cloud Agents (ocagents) - Precompiled Standalone Binary & Universal Runner
class Ocagents < Formula
  desc "Universal CLI & specialist agents for Cloud Architecture, DevSecOps, SRE, and FinOps"
  homepage "https://open-cloud-agents.github.io/ocagents/"
  license "Apache-2.0"
  version "2.2.1"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.1/ocagents-darwin-arm64.tar.gz"
    sha256 "8dd35b078f009b1b194e6c01acb1ef052127b0d83bfa81d9c3f64faeb4f65e37"
  end

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.1/ocagents-darwin-amd64.tar.gz"
    sha256 "e6521b679ed290d36315cb0d1327894b0682ea0bceea83e3cd492f790537cc74"
  end

  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.1/ocagents-linux-amd64.tar.gz"
    sha256 "c097efa06d1af4e32219d9adf8e2d382740209dadf1e37e5a12e796b529dba66"
  end

  if OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/open-cloud-agents/ocagents/releases/download/v2.2.1/ocagents-linux-arm64.tar.gz"
    sha256 "2d0dcf5a8bf07b274c928686ad54dcf5ec69f490ab145374584d5a6dfed1f8dd"
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
