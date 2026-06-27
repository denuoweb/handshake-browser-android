plugins {
    alias(libs.plugins.android.application)
}

val rustJniLibsDir = layout.buildDirectory.dir("generated/rustJniLibs")
val rustJniLibsDirFile = rustJniLibsDir.get().asFile
val buildRustAndroid = tasks.register<Exec>("buildRustAndroid") {
    val rootDir = rootProject.layout.projectDirectory.asFile.parentFile
    val script = rootDir.resolve("scripts/build-rust-android.sh")

    workingDir = rootDir
    commandLine("bash", script.absolutePath, rustJniLibsDirFile.absolutePath)

    environment("ANDROID_NDK_HOME", System.getenv("ANDROID_NDK_HOME") ?: System.getenv("ANDROID_NDK_ROOT") ?: "")
    environment("ANDROID_NDK_ROOT", System.getenv("ANDROID_NDK_ROOT") ?: System.getenv("ANDROID_NDK_HOME") ?: "")

    inputs.files(
        fileTree(rootDir.resolve("rust/crates")) {
            include("**/*.rs")
            include("**/*.toml")
        },
        rootDir.resolve("rust/Cargo.toml"),
        rootDir.resolve("rust/Cargo.lock"),
    )
    outputs.dir(rustJniLibsDir)
}

android {
    namespace = "com.handshake.browser"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.handshake.browser"
        minSdk = 34
        targetSdk = 37
        versionCode = 2
        versionName = "0.1.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        jniLibs.keepDebugSymbols += "**/libhns_browser_ffi.so"
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(rustJniLibsDirFile.absolutePath)
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildRustAndroid)
}

dependencies {
    implementation(libs.androidx.activity)
    implementation(libs.androidx.core)
    implementation(libs.androidx.webkit)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
