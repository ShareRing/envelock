// envelock's native Android example.
//
// A single-screen Compose app that walks the whole lifecycle: enroll, lock, unlock, read and
// write records, recover, destroy.
plugins {
    id("com.android.application") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "1.9.24"
}

android {
    namespace = "network.sharering.envelock.demo"
    compileSdk = 35

    defaultConfig {
        applicationId = "network.sharering.envelock.demo"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }

    sourceSets["main"].kotlin.srcDirs("src/main/kotlin")
    // The BIP-39 wordlist the SDK demo draws its 12 words from, shared with the iOS and React
    // Native examples so there is exactly one copy of it.
    sourceSets["main"].assets.srcDir("../shared")

    buildTypes {
        debug { isMinifyEnabled = false }
        release {
            // Minified on purpose: it proves the consumer ProGuard rules that keep the JNA
            // callback classes actually work. Stripping them fails only at runtime, in
            // release, which is the worst possible time to find out.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

dependencies {
    // By coordinates, not by project: this example is a consumer, and depending on the
    // published artifact is what makes it a real test of one.
    implementation("network.sharering:envelock-android:0.1.0")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
