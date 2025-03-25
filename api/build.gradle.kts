plugins {
    id("build.library")
    id("build.publish")
}

dependencies {

    api(libs.midnight.cfg.api)
    api(libs.midnight.cfg.codec.json)
    api(libs.midnight.lib)

    compileOnlyApi(libs.jetbrains.annotations)
    compileOnly(libs.jetbrains.annotations)
    implementation(libs.slf4j.api)
    testRuntimeOnly(libs.slf4j.simple)
}