plugins {
    id("build.application")
    id("build.shadow")
}

dependencies {

    implementation(project(":api"))
    shadow(project(":api"))

}

application {
    mainClass = "org.wallentines.jwt.util.Main"
}