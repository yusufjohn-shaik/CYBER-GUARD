use cyberguard_sca::models::{Ecosystem, Package};

#[test]
fn test_package_creation_and_purl_generation() {
    // 1. Cargo package
    let cargo_pkg = Package::new("tokio", "1.40.0", Ecosystem::Cargo, None, true);
    assert_eq!(cargo_pkg.purl, "pkg:cargo/tokio@1.40.0");
    assert_eq!(cargo_pkg.ecosystem, Ecosystem::Cargo);
    assert!(cargo_pkg.is_direct);

    // 2. Unscoped npm package
    let npm_pkg = Package::new("lodash", "4.17.21", Ecosystem::Npm, None, false);
    assert_eq!(npm_pkg.purl, "pkg:npm/lodash@4.17.21");

    // 3. Scoped npm package (@scope/name)
    let scoped_npm = Package::new("@types/node", "18.11.0", Ecosystem::Npm, None, false);
    assert_eq!(scoped_npm.purl, "pkg:npm/%40types/node@18.11.0");

    // 4. PyPI package
    let pypi_pkg = Package::new("requests", "2.31.0", Ecosystem::PyPi, None, true);
    assert_eq!(pypi_pkg.purl, "pkg:pypi/requests@2.31.0");
}
