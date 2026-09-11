allprojects {
    repositories {
        google()
        mavenCentral()
        // envelock's AAR, resolved from the local Maven repository during development. A real
        // release publishes to Maven Central and this line is unnecessary.
        //
        // Publish it first, from the repository root:
        //   ./gradlew :envelock-android:publishToMavenLocal
        mavenLocal()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
