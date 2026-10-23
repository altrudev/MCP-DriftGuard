plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "dev.frequency.guardian"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.frequency.guardian"
        minSdk = 30
        targetSdk = 35
        versionCode = 3
        versionName = "0.3.0"
    }
    buildFeatures { buildConfig = true }
    buildTypes { release { isMinifyEnabled = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
