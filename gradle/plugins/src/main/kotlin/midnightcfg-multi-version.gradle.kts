plugins {
    id("java")
    id("java-library")
    id("org.wallentines.gradle-multi-version")
    id("org.wallentines.gradle-patch")
}


multiVersion {
    useSourceDirectorySets()
    defaultVersion(21)
    additionalVersions(17,11,8)
}

patch {
    patchSet("java8", sourceSets["main"], sourceSets["main"].java, multiVersion.getCompileTask(8))
    patchSet("java11", sourceSets["main"], sourceSets["main"].java, multiVersion.getCompileTask(11))
    patchSet("java17", sourceSets["main"], sourceSets["main"].java, multiVersion.getCompileTask(17))
}
