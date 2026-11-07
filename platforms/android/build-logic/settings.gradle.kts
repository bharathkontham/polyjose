// The build logic shared by `:polyjose` and `:polyjose-jvm` (ADR 0033 §1, §4): the
// thirdPartyNotices task, the workspace version and the POM. Written in Java against the Gradle
// API only (`java-gradle-plugin` is a core Gradle plugin), so it needs no repository and adds no
// plugin or library to the build (feature 0008 T04, dependencies refinement).
rootProject.name = "build-logic"
