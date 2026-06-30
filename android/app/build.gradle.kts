import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.android.application)
}

val playUploadStoreFile = providers.environmentVariable("HNS_BROWSER_UPLOAD_STORE_FILE").orNull
val playUploadStorePassword = providers.environmentVariable("HNS_BROWSER_UPLOAD_STORE_PASSWORD").orNull
val playUploadKeyAlias = providers.environmentVariable("HNS_BROWSER_UPLOAD_KEY_ALIAS").orNull
val playUploadKeyPassword = providers.environmentVariable("HNS_BROWSER_UPLOAD_KEY_PASSWORD").orNull
val playSigningConfigured = listOf(
    playUploadStoreFile,
    playUploadStorePassword,
    playUploadKeyAlias,
    playUploadKeyPassword,
).all { !it.isNullOrBlank() }

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
        versionCode = 13
        versionName = "0.2.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (playSigningConfigured) {
            create("playUpload") {
                storeFile = file(playUploadStoreFile!!)
                storePassword = playUploadStorePassword
                keyAlias = playUploadKeyAlias
                keyPassword = playUploadKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            if (playSigningConfigured) {
                signingConfig = signingConfigs.getByName("playUpload")
            }
            ndk {
                debugSymbolLevel = "FULL"
            }
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

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(rustJniLibsDirFile.absolutePath)
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildRustAndroid)
}

tasks.register("verifyPlayReleaseBundle") {
    group = "verification"
    description = "Builds the release AAB and fails if it is not signed for Google Play upload."
    dependsOn("bundleRelease")

    doLast {
        check(playSigningConfigured) {
            "Play upload signing is not configured. Set HNS_BROWSER_UPLOAD_STORE_FILE, " +
                "HNS_BROWSER_UPLOAD_STORE_PASSWORD, HNS_BROWSER_UPLOAD_KEY_ALIAS, and " +
                "HNS_BROWSER_UPLOAD_KEY_PASSWORD before uploading to Play Console."
        }

        val bundle = layout.buildDirectory.file("outputs/bundle/release/app-release.aab").get().asFile
        check(bundle.isFile) { "Release app bundle was not found at ${bundle.absolutePath}" }
        val hasJarSignature = ZipFile(bundle).use { zip ->
            zip.entries().asSequence().any { entry ->
                entry.name.startsWith("META-INF/") &&
                    (entry.name.endsWith(".RSA") || entry.name.endsWith(".DSA") || entry.name.endsWith(".EC"))
            }
        }
        check(hasJarSignature) { "Release app bundle exists but is not signed." }

        val nativeLibraries = ZipFile(bundle).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { it.endsWith(".so") }
                .sorted()
                .toList()
        }
        val requiredLibraries = setOf(
            "base/lib/arm64-v8a/libhns_browser_ffi.so",
            "base/lib/x86_64/libhns_browser_ffi.so",
        )
        check(nativeLibraries.containsAll(requiredLibraries)) {
            "Release app bundle is missing required 64-bit native libraries. Found: $nativeLibraries"
        }
    }
}

dependencies {
    implementation(libs.androidx.activity)
    implementation(libs.androidx.core)
    implementation(libs.androidx.webkit)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
