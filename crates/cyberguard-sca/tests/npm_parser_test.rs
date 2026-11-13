use cyberguard_sca::models::Ecosystem;
use cyberguard_sca::parsers::NpmLockParser;
use cyberguard_sca::traits::LockfileParser;
use std::path::Path;

#[test]
fn test_npm_lock_parser_v2_v3_packages() {
    let json_content = r#"{
  "name": "my-express-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "my-express-app",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2"
      },
      "devDependencies": {
        "@types/node": "^18.11.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iVEkiGu9P0Y6374fNAx4cbQeDXSqc188KxK5h0aH5YwP5iQ=="
    },
    "node_modules/@types/node": {
      "version": "18.11.0",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-18.11.0.tgz",
      "integrity": "sha512-IO/0UMSLBn1pnzgh0u7i8pA6QJ8x9pW3k7P0eF4N6/vE1V4f4A==",
      "dev": true
    },
    "node_modules/express/node_modules/ms": {
      "version": "2.0.0",
      "integrity": "sha512-ms-test=="
    }
  }
}"#;

    let parser = NpmLockParser::new();
    assert!(parser.can_parse(Path::new("package-lock.json")));
    assert!(parser.can_parse(Path::new("frontend/package-lock.json")));
    assert!(!parser.can_parse(Path::new("Cargo.lock")));

    let packages = parser
        .parse(Path::new("package-lock.json"), json_content)
        .unwrap();

    assert_eq!(packages.len(), 3);

    let express = packages.iter().find(|p| p.name == "express").unwrap();
    assert_eq!(express.version, "4.18.2");
    assert_eq!(express.ecosystem, Ecosystem::Npm);
    assert_eq!(express.purl, "pkg:npm/express@4.18.2");
    assert_eq!(
        express.checksum.as_deref(),
        Some("sha512-5/PsL6iVEkiGu9P0Y6374fNAx4cbQeDXSqc188KxK5h0aH5YwP5iQ==")
    );

    let scoped = packages.iter().find(|p| p.name == "@types/node").unwrap();
    assert_eq!(scoped.version, "18.11.0");
    assert_eq!(scoped.purl, "pkg:npm/%40types/node@18.11.0");

    let nested_ms = packages.iter().find(|p| p.name == "ms").unwrap();
    assert_eq!(nested_ms.version, "2.0.0");
}

#[test]
fn test_npm_lock_parser_v1_dependencies() {
    let json_content = r#"{
  "name": "legacy-app",
  "version": "0.1.0",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.20",
      "integrity": "sha512-W4w/..."
    },
    "debug": {
      "version": "2.6.9",
      "integrity": "sha512-debug==",
      "dependencies": {
        "ms": {
          "version": "2.0.0"
        }
      }
    }
  }
}"#;

    let parser = NpmLockParser::new();
    let packages = parser
        .parse(Path::new("package-lock.json"), json_content)
        .unwrap();

    assert_eq!(packages.len(), 3);
    assert!(packages
        .iter()
        .any(|p| p.name == "lodash" && p.version == "4.17.20"));
    assert!(packages
        .iter()
        .any(|p| p.name == "debug" && p.version == "2.6.9"));
    assert!(packages
        .iter()
        .any(|p| p.name == "ms" && p.version == "2.0.0"));
}
