"""Language and ecosystem recognition.

Language recognition is deliberately separated from rule implementation:
rules declare which ecosystems they apply to via
:func:`matches_language`, and new languages can be added to this registry
without touching the core engine.

Recognition is filename/extension based. It powers the capability matrix
(docs/supported-languages.md), per-ecosystem rule targeting and reporting.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Ecosystem:
    """One language or ecosystem AgentPreflight can recognise."""

    id: str
    display_name: str
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()
    notes: str = ""
    status: str = "supported"  # supported | partial | experimental


# Registered ecosystems. Content rules (secrets, generic assignments) are
# language-agnostic and apply to all text files regardless of this table.
ECOSYSTEMS: tuple[Ecosystem, ...] = (
    Ecosystem(
        "python",
        "Python",
        (".py", ".pyi", ".pyw"),
        filenames=("requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg"),
    ),
    Ecosystem("javascript", "JavaScript", (".js", ".mjs", ".cjs"), filenames=("package.json",)),
    Ecosystem("typescript", "TypeScript", (".ts", ".mts", ".cts", ".tsx")),
    Ecosystem("jsx", "React / JSX", (".jsx",)),
    Ecosystem("java", "Java", (".java",), filenames=("pom.xml",)),
    Ecosystem("kotlin", "Kotlin", (".kt", ".kts")),
    Ecosystem("swift", "Swift", (".swift",), filenames=("Package.swift",)),
    Ecosystem(
        "objective-c",
        "Objective-C",
        (".m", ".h"),
        notes="`.m`/`.h` also used by MATLAB/Objective-C headers; treated as Objective-C.",
    ),
    Ecosystem("c", "C", (), notes="See `c-family`."),
    Ecosystem(
        "c-family",
        "C / C++",
        (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
        filenames=("CMakeLists.txt", "Makefile"),
    ),
    Ecosystem("csharp", "C#", (".cs",), filenames=(".csproj",)),
    Ecosystem("go", "Go", (".go",), filenames=("go.mod", "go.sum")),
    Ecosystem("rust", "Rust", (".rs",), filenames=("Cargo.toml", "Cargo.lock")),
    Ecosystem("ruby", "Ruby", (".rb",), filenames=("Gemfile", "Gemfile.lock", "Rakefile")),
    Ecosystem("php", "PHP", (".php",), filenames=("composer.json", "composer.lock")),
    Ecosystem("perl", "Perl", (".pl", ".pm", ".t")),
    Ecosystem("lua", "Lua", (".lua",)),
    Ecosystem("r", "R", (".r", ".R"), notes="Handled as `.r` (case-insensitive match)."),
    Ecosystem("julia", "Julia", (".jl",), filenames=("Project.toml",)),
    Ecosystem("dart", "Dart", (".dart",), filenames=("pubspec.yaml",)),
    Ecosystem("elixir", "Elixir", (".ex", ".exs"), filenames=("mix.exs",)),
    Ecosystem("erlang", "Erlang", (".erl", ".hrl"), filenames=("rebar.config",)),
    Ecosystem("scala", "Scala", (".scala", ".sc")),
    Ecosystem("groovy", "Groovy", (".groovy", ".gradle"), filenames=("build.gradle", "settings.gradle")),
    Ecosystem("clojure", "Clojure", (".clj", ".cljs", ".cljc", ".edn")),
    Ecosystem("fsharp", "F#", (".fs", ".fsx")),
    Ecosystem("vbnet", "Visual Basic .NET", (".vb",), filenames=(".vbproj",)),
    Ecosystem("powershell", "PowerShell", (".ps1", ".psm1", ".psd1")),
    Ecosystem("shell", "Shell / Bash / Zsh / Fish", (".sh", ".bash", ".zsh", ".fish", ".ksh")),
    Ecosystem("solidity", "Solidity", (".sol",)),
    Ecosystem("move", "Move", (".move",)),
    Ecosystem("haskell", "Haskell", (".hs", ".lhs"), filenames=("stack.yaml", "cabal.project")),
    Ecosystem("ocaml", "OCaml", (".ml", ".mli"), filenames=("dune", "dune-project")),
    Ecosystem("fortran", "Fortran", (".f", ".for", ".f90", ".f95", ".f03")),
    Ecosystem("cobol", "COBOL", (".cbl", ".cob")),
    Ecosystem("assembly", "Assembly", (".asm", ".s", ".S")),
    Ecosystem("sql", "SQL", (".sql",), filenames=(".sqlfluff",)),
    Ecosystem("html", "HTML", (".html", ".htm", ".xhtml")),
    Ecosystem("css", "CSS", (".css", ".scss", ".sass", ".less", ".styl")),
    Ecosystem("vue", "Vue", (".vue",)),
    Ecosystem("svelte", "Svelte", (".svelte",)),
    Ecosystem("graphql", "GraphQL", (".graphql", ".gql")),
    Ecosystem("protobuf", "Protocol Buffers", (".proto",)),
    Ecosystem("wasm", "WebAssembly project files", (".wat", ".wast"), status="experimental"),
    # Configuration / infrastructure ecosystems
    Ecosystem("json", "JSON / JSONC", (".json", ".jsonc"), status="partial"),
    Ecosystem("yaml", "YAML", (".yaml", ".yml"), status="supported"),
    Ecosystem("toml", "TOML", (".toml",), status="supported"),
    Ecosystem("xml", "XML", (".xml", ".xsl", ".plist"), status="partial"),
    Ecosystem(
        "ini",
        "INI / properties",
        (".ini", ".cfg", ".conf", ".properties", ".env", ".envrc"),
        status="supported",
    ),
    Ecosystem(
        "docker",
        "Docker",
        (),
        filenames=(
            "Dockerfile",
            "Dockerfile.dev",
            "Dockerfile.prod",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ),
    ),
    Ecosystem(
        "kubernetes",
        "Kubernetes",
        (),
        notes="Detected via path/kind heuristics in YAML files.",
        status="partial",
    ),
    Ecosystem("helm", "Helm", (), filenames=("Chart.yaml", "values.yaml", "values.yml"), status="partial"),
    Ecosystem(
        "terraform",
        "Terraform / OpenTofu",
        (".tf", ".tfvars"),
        filenames=("main.tf", "variables.tf"),
        status="partial",
    ),
    Ecosystem(
        "ansible",
        "Ansible",
        (),
        filenames=("ansible.cfg", "site.yml", "playbook.yml"),
        status="partial",
    ),
    Ecosystem("nix", "Nix", (".nix",), status="experimental"),
    Ecosystem(
        "github-actions",
        "GitHub Actions",
        (),
        filenames=("action.yml", "action.yaml"),
        notes="Workflows under `.github/workflows/` are detected by path.",
        status="supported",
    ),
    Ecosystem("gitlab-ci", "GitLab CI", (), filenames=(".gitlab-ci.yml",), status="partial"),
    Ecosystem("jenkins", "Jenkins", (), filenames=("Jenkinsfile",), status="partial"),
    Ecosystem(
        "android",
        "Android",
        (),
        filenames=("AndroidManifest.xml", "build.gradle", "gradle.properties"),
        status="partial",
    ),
    Ecosystem(
        "ios",
        "iOS / Apple platforms",
        (".xib", ".storyboard"),
        filenames=("Info.plist", "Podfile", "project.pbxproj"),
        status="partial",
    ),
)

_EXT_MAP: dict[str, str] = {}
_NAME_MAP: dict[str, str] = {}

for _eco in ECOSYSTEMS:
    if _eco.id == "c":  # placeholder entry; real mapping lives in c-family
        continue
    for _ext in _eco.extensions:
        _EXT_MAP.setdefault(_ext.lower(), _eco.id)
    for _name in _eco.filenames:
        _NAME_MAP.setdefault(_name.lower(), _eco.id)

# '.r' vs '.R' — treat case-insensitively (registered above via .r).


def detect_language(rel_path: str) -> str | None:
    """Return the ecosystem id for a file path, or ``None`` if unknown."""
    parts = rel_path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == ".github" and parts[1] == "workflows" and parts[-1].endswith((".yml", ".yaml")):
        return "github-actions"
    filename = parts[-1].lower() if parts else ""
    if filename in _NAME_MAP:
        lang = _NAME_MAP[filename]
        # Gradle files belong to the JVM ecosystem whichever language is used.
        if filename == "build.gradle" and any(p == "android" for p in parts[:-1]):
            return "android"
        return lang
    stem = filename
    while "." in stem:
        stem = stem.split(".", 1)[1]
        ext = "." + stem
        if ext in _EXT_MAP:
            return _EXT_MAP[ext]
    # extension-less common names
    return _NAME_MAP.get(filename)


def language_display(lang_id: str | None) -> str:
    if lang_id is None:
        return "unknown"
    for eco in ECOSYSTEMS:
        if eco.id == lang_id:
            return eco.display_name
    return lang_id


def ecosystem_summary() -> list[dict[str, object]]:
    """Table data for docs/supported-languages.md."""
    return [
        {
            "id": eco.id,
            "name": eco.display_name,
            "status": eco.status,
            "extensions": list(eco.extensions),
            "filenames": list(eco.filenames),
            "notes": eco.notes,
        }
        for eco in ECOSYSTEMS
    ]
