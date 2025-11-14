cmake_minimum_required(VERSION 3.17)
project(FIPS205_Project C CXX)

# Enable C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags for AVX/SHA/etc
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -mtune=native -mavx2 -fopenmp -mfma -funroll-loops -finline-functions -ffast-math -fcommon -fno-lto")

# Include directories
include_directories(
        ${PROJECT_SOURCE_DIR}      # current folder
        ${PROJECT_SOURCE_DIR}/OLD  # old headers
)

add_compile_options(-Wno-implicit-function-declaration -Wno-deprecated-declarations)
add_compile_options(-Wno-incompatible-pointer-types)
add_compile_options(-Wno-implicit-int)

# Source files
set(SOURCES
        AVX256.c
        AVX512.c
        AVXconst.c
        Common.c
        fips202.c
        FIPS205_internal.c
        FIPS_205_fors.c
        FIPS_205_fors_old.c
        FIPS_205_ht.c
        FIPS_205_ht_old.c
        FIPS_205_internal_old.c
        FIPS_205_json.c
        FIPS_205_xmss_old.c
        FIPS_205_Addr.c
        FIPS_205_Common_fun_old.c
        FIPS_205_hashs.c
        FIPS_205_hashs_old.c
        FIPS_205_WOTS.c
        FIPS_205_wots_old.c
        FIPS_205_xmss.c
        main.c
        OLD/address.c
        OLD/fors.c
        OLD/hash_sha256.c
        OLD/hash_sha256x8.c
        OLD/sha256.c
        OLD/sha256avx.c
        OLD/sha256x8.c
        OLD/sign.c
        OLD/thash_sha256_simple.c
        OLD/thash_sha256_simplex8.c
        OLD/utils.c
        OLD/utilsx8.c
        OLD/wots.c
        print.c
        SHA256_device.c
        sha256_old.c
        SHA512.c
        Test.c
)

# Add executable
add_executable(Test ${SOURCES})

# Link math library
target_link_libraries(Test m)
target_compile_definitions(Test PRIVATE _PREDCALC _JSON_FILE_)