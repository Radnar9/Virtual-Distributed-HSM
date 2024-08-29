plugins {
    kotlin("jvm") version "2.0.0"
    distribution
    id("org.hidetake.ssh") version "2.11.2" apply true
}

group = "hsm"
version = "1.0"

repositories {
    mavenCentral()
}

distributions {
    main {
        contents {
            into("config") {
                from("config")
            }
            into("pairing") {
                from("pairing")
            }
            into("lib") {
                from(tasks.named<Jar>("jar").get())
                from(configurations.runtimeClasspath)
            }
            from("scripts")
        }
    }
}

// https://github.com/int128/gradle-ssh-plugin/issues/317
tasks.register("remoteDeploy") {
    dependsOn("installDist")
    val myServer = org.hidetake.groovy.ssh.core.Remote(mapOf<String, String>(
        "host" to "192.168.10.100", // <host ip>
        "user" to "root",           // <host user>
        "password" to "root",       // <host password>
        "fileTransfer" to "scp",
        //identity = file(System.getProperty("user.home") + System.getProperty("file.separator")
        //        + ".ssh" + System.getProperty("file.separator") + "id_rsa") // identity=file("<ssh private key file>")
    ))

    doLast {
        ssh.run(delegateClosureOf<org.hidetake.groovy.ssh.core.RunHandler> {
            session(myServer, delegateClosureOf<org.hidetake.groovy.ssh.session.SessionHandler> {
                put(hashMapOf("from" to "build/install/${project.name}", "into" to "~/")) // "into" to "/home/<username>/"
            })
        })
    }
}

tasks.register("localDeploy") {
    dependsOn("installDist")

    doLast {
        val replicas = intArrayOf(0, 1, 2, 3)
        val clients = intArrayOf(0)

        val dst = "${System.getProperty("user.home")}${File.separator}Desktop${File.separator}${project.name}${File.separator}"
        println("Deploying project into $dst")

        replicas.forEach { replicaId ->
            val target = "$dst${File.separator}rep$replicaId"
            copy {
                from("build/install/${project.name}")
                into(target)
            }
        }

        clients.forEach { clientId ->
            val target = "$dst${File.separator}cli$clientId"
            copy {
                from("build/install/${project.name}")
                into(target)
            }
        }
    }
}

tasks.register("simpleLocalDeploy") {
    dependsOn("installDist")

    doLast {
        val buildDir = project.layout.buildDirectory.asFile.get()
        val src = "${buildDir}${File.separator}install${File.separator}${project.name}"
        val workingDirectory = "${buildDir}${File.separator}local${File.separator}"

        copy {
            from(src)
            into(workingDirectory)
        }
    }
}

dependencies {
    implementation(fileTree("libs") { include("*.jar") })

    // https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk18on
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")

    // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")

    // https://mvnrepository.com/artifact/commons-codec/commons-codec
    implementation("commons-codec:commons-codec:1.15")

    // https://mvnrepository.com/artifact/ch.qos.logback/logback-core
    implementation("ch.qos.logback:logback-core:1.4.14")

    // https://mvnrepository.com/artifact/ch.qos.logback/logback-classic
    implementation("ch.qos.logback:logback-classic:1.4.12")

    // https://mvnrepository.com/artifact/io.netty/netty-all
    implementation("io.netty:netty-all:4.1.112.Final")

    // https://mvnrepository.com/artifact/org.slf4j/slf4j-api
    implementation("org.slf4j:slf4j-api:1.7.32")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0-RC")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}