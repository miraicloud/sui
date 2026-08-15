// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let service = tonic_build::manual::Service::builder()
        .name("ValidatorSigner")
        .package("sui_validator_signer")
        .comment("Fenced validator signing interface")
        .method(
            tonic_build::manual::Method::builder()
                .name("execute")
                .route_name("Execute")
                .input_type("crate::rpc::RpcRequest")
                .output_type("crate::rpc::RpcResponse")
                .codec_path("tonic_prost::ProstCodec")
                .build(),
        )
        .build();

    tonic_build::manual::Builder::new().compile(&[service]);
    println!("cargo:rerun-if-changed=build.rs");
}
