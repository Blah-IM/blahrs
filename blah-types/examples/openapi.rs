#![expect(clippy::print_stdout, reason = "allowed to dump OAPI")]

fn main() {
    let json = blah_types::openapi()
        .to_pretty_json()
        .expect("serialization cannot fail");
    println!("{json}");
}
