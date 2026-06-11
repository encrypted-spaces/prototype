fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["src/proto/database.proto"], &["src/proto/"])?;
    Ok(())
}
