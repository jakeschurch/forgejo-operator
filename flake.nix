{
  description = "Declarative Forgejo Kubernetes operator";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      # Go build inputs only. Docs, charts, CRDs, Makefile, beads data and the
      # flake itself stay out, so editing them keeps the package outPath (and
      # so the farm/CSI cache hit) unchanged. No Go source uses go:embed and
      # no package ships testdata; if either appears, add it here.
      mkSrc = lib: { keep ? ./. }: lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.intersection keep (lib.fileset.unions [
          ./go.mod
          ./go.sum
          (lib.fileset.fileFilter (file: file.hasExt "go") ./.)
        ]);
      };
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          operator = pkgs.buildGoModule {
            pname = "forgejo-operator";
            version = "0.1.0";
            src = mkSrc pkgs.lib { };
            vendorHash = "sha256-xr0iDFo2mxsZ4KPs/3qV6UP48PCGQ5JgD8uQXOPPSdk=";
            subPackages = [ "cmd/manager" ];
            ldflags = [ "-s" "-w" ];
            env.CGO_ENABLED = "0";
            postInstall = "mv $out/bin/manager $out/bin/forgejo-operator";
          };
          # Same binary without the in-build `go test`. The image ships this
          # one: tests run once, in testReport (a farm cache hit on an
          # unchanged Go source tree), not again inside the image build.
          unchecked = operator.overrideAttrs (_: { doCheck = false; });
        in {
          default = operator;
          # Test report for the Margo `nix-go-test` check: go vet and
          # `go test -json` run in the sandbox with the pinned toolchain and the
          # operator's vendored modules. Never fails the build: the verdict is
          # in $out/exit-code (0 = vet and tests passed) and the check reads it.
          # Integration tests skip without FORGEJO_BIN, as in the default build.
          testReport = operator.overrideAttrs (old: {
            pname = "forgejo-operator-test-report";
            doCheck = false;
            dontFixup = true;
            postInstall = "";
            buildPhase = ''
              runHook preBuild
              export HOME=$TMPDIR
              mkdir -p $out
              vet=0; tst=0
              go vet ./... > $out/vet.log 2>&1 || vet=$?
              go test -json ./... > $out/go.json 2> $out/test.stderr || tst=$?
              if [ "$vet" -ne 0 ]; then rc=$vet; else rc=$tst; fi
              echo "$rc" > $out/exit-code
              runHook postBuild
            '';
            installPhase = "true";
          });
          image = pkgs.dockerTools.buildLayeredImage {
            name = "harbor.oci-registry.svc.cluster.local/foundry/forgejo-operator";
            tag = "latest";
            contents = [ pkgs.cacert ];
            config = {
              Entrypoint = [ "${unchecked}/bin/forgejo-operator" ];
              User = "65532:65532";
            };
          };
        });
      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          operator = self.packages.${system}.default;
          report = self.packages.${system}.testReport;
          inherit (pkgs) lib;
          # 2026-11-12: remove documentation/metadata to model its strongest edit.
          fs = lib.fileset;
          docFiles = fs.difference
            (fs.fileFilter (file:
              file.hasExt "md" || lib.hasPrefix "README" file.name
              || lib.hasPrefix "CHANGELOG" file.name
              || builtins.elem file.name [ "AGENTS.md" "CLAUDE.md" "Makefile" "flake.nix" "flake.lock" "Dockerfile" "mkdocs.yml" ]) ./.)
            (fs.unions [ ]);
          docOnly = fs.unions ([ docFiles ] ++ map fs.maybeMissing [
            ./docs ./documentation ./.forgejo ./.github ./.beads ./charts ./deploy ./config ./ci
          ]);
          without = remove: mkSrc lib { keep = fs.difference ./. remove; };
          srcStability =
            assert (without docOnly).outPath == operator.src.outPath;
            assert (without ./go.mod).outPath != operator.src.outPath;
            pkgs.runCommand "forgejo-operator-src-stability" { } "touch $out";
        in {
          inherit (self.packages.${system}) default;
          src-stability = srcStability;
          tests = operator;
          # The report derivation always builds; this is the check that fails
          # when vet or a test did.
          test-report = pkgs.runCommand "forgejo-operator-test-report-check" { } ''
            test -s ${report}/go.json
            test "$(cat ${report}/exit-code)" = 0
            touch $out
          '';
          # Only Go build inputs are in the source, so a docs-only change
          # cannot move the package outPath.
          source-scope = pkgs.runCommand "forgejo-operator-source-scope" { } ''
            cd ${mkSrc pkgs.lib { }}
            bad=$(find . -type f ! -name '*.go' ! -name go.mod ! -name go.sum)
            if [ -n "$bad" ]; then echo "non-Go-build files in source:" "$bad"; exit 1; fi
            touch $out
          '';
          chart = pkgs.runCommand "forgejo-operator-chart" {
            nativeBuildInputs = [ pkgs.kubernetes-helm (pkgs.python3.withPackages (ps: [ ps.pyyaml ])) ];
          } ''
            cp -R ${self}/charts/forgejo-operator chart
            chmod -R u+w chart
            helm lint chart
            helm template forgejo-operator chart >/dev/null
            python3 chart/rollout_test.py
            touch $out
          '';
        });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.mkShell { packages = [ pkgs.go pkgs.gopls pkgs.kubernetes-helm pkgs.kubebuilder pkgs.gnumake (pkgs.python3.withPackages (ps: [ ps.pyyaml ])) ]; };
        });
    };
}
