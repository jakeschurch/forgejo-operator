{
  description = "Declarative Forgejo Kubernetes operator";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          operator = pkgs.buildGoModule {
            pname = "forgejo-operator";
            version = "0.1.0";
            src = self;
            vendorHash = "sha256-onlkkR5+tdwqCMcxMAzydUjxtGgH3d3HTUQYB8IJzjI=";
            subPackages = [ "cmd/manager" ];
            ldflags = [ "-s" "-w" ];
            env.CGO_ENABLED = "0";
            postInstall = "mv $out/bin/manager $out/bin/forgejo-operator";
          };
        in {
          default = operator;
          image = pkgs.dockerTools.buildLayeredImage {
            name = "harbor.oci-registry.svc.cluster.local/foundry/forgejo-operator";
            tag = "latest";
            contents = [ pkgs.cacert ];
            config = {
              Entrypoint = [ "${operator}/bin/forgejo-operator" ];
              User = "65532:65532";
            };
          };
        });
      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          operator = self.packages.${system}.default;
        in {
          inherit (self.packages.${system}) default;
          tests = operator;
          chart = pkgs.runCommand "forgejo-operator-chart" {
            nativeBuildInputs = [ pkgs.kubernetes-helm ];
          } ''
            cp -R ${self}/charts/forgejo-operator chart
            chmod -R u+w chart
            helm lint chart
            helm template forgejo-operator chart >/dev/null
            touch $out
          '';
        });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.mkShell { packages = [ pkgs.go pkgs.gopls pkgs.kubernetes-helm pkgs.kubebuilder ]; };
        });
    };
}
