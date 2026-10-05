plugins {
    java
}

group = "com.blanche"
version = "0.1.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.11")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

tasks.jar {
    archiveBaseName.set("blanche-burp-extension")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    )
    manifest {
        attributes(
            "Implementation-Title" to "BLANCHE Burp Extension",
            "Implementation-Version" to project.version
        )
    }
}
