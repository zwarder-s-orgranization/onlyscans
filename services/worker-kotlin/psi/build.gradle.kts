plugins {
    kotlin("jvm") version "2.2.21"
    id("com.gradleup.shadow") version "8.3.6"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-compiler-embeddable:2.2.21")
    implementation("org.yaml:snakeyaml:2.3")
}

kotlin {
    jvmToolchain(21)
}

tasks.shadowJar {
    archiveFileName.set("secflow-psi.jar")
    manifest {
        attributes["Main-Class"] = "secflow.PsiScanKt"
    }
    mergeServiceFiles()
}
