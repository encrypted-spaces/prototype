fn main() {
    encrypted_spaces_sdk_codegen::compile("../app_schema.kdl").expect("sdk-codegen failed");
    tauri_build::build();
}
