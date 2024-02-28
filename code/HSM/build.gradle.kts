plugins {
    kotlin("jvm") version "1.9.22"
    distribution
    id("org.hidetake.ssh") version "2.11.2" apply true
}

group = "hsm"
version = "0.1"

repositories {
    mavenCentral()
}

distributions {
    main {
        contents {
            into("config") {
                from("config")
            }
            into("lib") {
                from("jar")
                from(configurations.runtimeClasspath)
            }
            from("runscripts")
        }
    }
}

// https://github.com/int128/gradle-ssh-plugin/issues/317
tasks.register("remoteDeploy") {
    dependsOn("installDist")
    val myServer = org.hidetake.groovy.ssh.core.Remote(mapOf<String, String>(
        "host" to "192.168.10.100",
        "user" to "root",
        "password" to "root",
        "fileTransfer" to "scp",
        //identity = file(System.getProperty("user.home") + System.getProperty("file.separator")
        //        + ".ssh" + System.getProperty("file.separator") + "id_rsa")
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

dependencies {
    implementation(fileTree("libs") { include("*.jar") })

    // https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")

    // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")

    // https://mvnrepository.com/artifact/commons-codec/commons-codec
    implementation("commons-codec:commons-codec:1.15")

    // https://mvnrepository.com/artifact/ch.qos.logback/logback-core
    implementation("ch.qos.logback:logback-core:1.4.12")

    // https://mvnrepository.com/artifact/ch.qos.logback/logback-classic
    implementation("ch.qos.logback:logback-classic:1.4.12")

    // https://mvnrepository.com/artifact/io.netty/netty-all
    implementation("io.netty:netty-all:4.1.106.Final")

    // https://mvnrepository.com/artifact/org.slf4j/slf4j-api
    implementation("org.slf4j:slf4j-api:1.7.32")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}