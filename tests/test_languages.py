"""Language/ecosystem registry tests."""

from __future__ import annotations

import pytest

from agentpreflight.languages import (
    ECOSYSTEMS,
    detect_language,
    ecosystem_summary,
    language_display,
)


class TestDetectLanguage:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("app.py", "python"),
            ("requirements.txt", "python"),
            ("pyproject.toml", "python"),
            ("src/index.js", "javascript"),
            ("package.json", "javascript"),
            ("Component.tsx", "typescript"),
            ("widget.jsx", "jsx"),
            ("Main.java", "java"),
            ("pom.xml", "java"),
            ("Main.kt", "kotlin"),
            ("Package.swift", "swift"),
            (" ViewController.m", "objective-c"),
            ("main.c", "c-family"),
            ("main.cpp", "c-family"),
            ("CMakeLists.txt", "c-family"),
            ("Program.cs", "csharp"),
            ("main.go", "go"),
            ("go.mod", "go"),
            ("main.rs", "rust"),
            ("Cargo.toml", "rust"),
            ("app.rb", "ruby"),
            ("Gemfile", "ruby"),
            ("index.php", "php"),
            ("script.pl", "perl"),
            ("game.lua", "lua"),
            ("plot.r", "r"),
            ("plot.R", "r"),
            ("model.jl", "julia"),
            ("main.dart", "dart"),
            ("pubspec.yaml", "dart"),
            ("app.ex", "elixir"),
            ("mix.exs", "elixir"),
            ("server.erl", "erlang"),
            ("App.scala", "scala"),
            ("build.gradle", "groovy"),
            ("core.clj", "clojure"),
            ("Calc.fs", "fsharp"),
            ("Form.vb", "vbnet"),
            ("setup.ps1", "powershell"),
            ("deploy.sh", "shell"),
            ("Contract.sol", "solidity"),
            ("Move.move", "move"),
            ("Main.hs", "haskell"),
            ("parser.ml", "ocaml"),
            ("legacy.f90", "fortran"),
            ("PAYROLL.cbl", "cobol"),
            ("boot.asm", "assembly"),
            ("query.sql", "sql"),
            ("page.html", "html"),
            ("style.scss", "css"),
            ("App.vue", "vue"),
            ("Widget.svelte", "svelte"),
            ("schema.graphql", "graphql"),
            ("msg.proto", "protobuf"),
            ("Dockerfile", "docker"),
            ("docker-compose.yml", "docker"),
            ("Chart.yaml", "helm"),
            ("values.yaml", "helm"),
            ("main.tf", "terraform"),
            ("ansible.cfg", "ansible"),
            (".gitlab-ci.yml", "gitlab-ci"),
            ("Jenkinsfile", "jenkins"),
            ("flake.nix", "nix"),
            ("action.yml", "github-actions"),
            (".github/workflows/ci.yml", "github-actions"),  # path-based detection
            ("data.json", "json"),
            ("conf.yaml", "yaml"),
            ("app.toml", "toml"),
            ("x.xml", "xml"),
            ("app.ini", "ini"),
            ("notes.txt", None),
            ("README", None),
        ],
    )
    def test_detection(self, path, expected):
        assert detect_language(path) == expected

    def test_android_manifest(self):
        assert detect_language("app/AndroidManifest.xml") == "android"

    def test_extension_case_insensitive(self):
        assert detect_language("plot.r") == "r"
        assert detect_language("PLOT.R") == "r"


class TestRegistry:
    def test_summary_rows(self):
        rows = ecosystem_summary()
        assert len(rows) == len(ECOSYSTEMS)
        for row in rows:
            assert {"id", "name", "status", "extensions"} <= set(row)

    def test_status_values(self):
        for eco in ECOSYSTEMS:
            assert eco.status in ("supported", "partial", "experimental")

    def test_display_names(self):
        assert language_display("python") == "Python"
        assert language_display(None) == "unknown"

    def test_unique_ids(self):
        ids = [eco.id for eco in ECOSYSTEMS]
        assert len(ids) == len(set(ids))
