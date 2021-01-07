#!/bin/sh
cross build --release --target=armv7-linux-androideabi
cross build --release --target=aarch64-linux-android
cross build --release --target=i686-linux-android

cp target/aarch64-linux-android/release/libsnark_prove_benchmark_ndk.so ~/AndroidStudioProjects/SnarkBenchmark2/app/src/main/jniLibs/arm64-v8a
cp target/armv7-linux-androideabi/release/libsnark_prove_benchmark_ndk.so ~/AndroidStudioProjects/SnarkBenchmark2/app/src/main/jniLibs/armeabi
cp target/i686-linux-android/release/libsnark_prove_benchmark_ndk.so ~/AndroidStudioProjects/SnarkBenchmark2/app/src/main/jniLibs/x86
