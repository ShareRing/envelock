// Gradle build for the envelock native Android example.
//
// Deliberately a **separate build** from the library in ../../platform/android. The example
// consumes `network.sharering:envelock-android` by coordinates, exactly as a real integrator
// does. Making it a sibling Gradle project instead would prove only that it compiles against
// the source tree - not that the published artifact actually works.
//
// Publish the library first:
//   cd ../../platform/android && ./gradlew publishToMavenLocal
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // Where the locally published envelock AAR lives. A real integrator resolves it from
        // Maven Central instead and does not need this line.
        mavenLocal()
    }
}

rootProject.name = "envelock-demo"
