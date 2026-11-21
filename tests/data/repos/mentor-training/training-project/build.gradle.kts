plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.9"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "lab.repairdesk"
version = "1.0.0"

repositories { mavenCentral() }

kotlin {
    jvmToolchain(21)
    compilerOptions.freeCompilerArgs.add("-Xannotation-default-target=param-property")
    providers.gradleProperty("organizerTests").orNull?.let { directory ->
        sourceSets.named("test") { kotlin.srcDir(directory) }
    }
}

val archiveFormatVersion = "1.25.0"
val manifestVersion = providers.gradleProperty("legacyManifestJsonVersion").get()

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("com.h2database:h2")

    implementation("org.apache.commons:commons-text:1.9")
    implementation("org.jsoup:jsoup:1.14.1")
    implementation("org.apache.commons:commons-compress:$archiveFormatVersion")
    add(
        "implementation",
        "commons-net:commons-net:3.8.0",
    )
    implementation("org.json:json:$manifestVersion")
    implementation("org.apache.commons:commons-lang3:3.20.0")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

configurations.named("runtimeClasspath") {
    resolutionStrategy.activateDependencyLocking()
}

tasks.test { useJUnitPlatform() }

tasks.register<Sync>("stageRuntimeJars") {
    from(configurations.runtimeClasspath)
    into(layout.buildDirectory.dir("sca-jars"))
    include("*.jar")
}
