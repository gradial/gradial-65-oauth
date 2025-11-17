# Gradial OAuth Installation Guide for Customers

This guide explains how to embed the Gradial OAuth package in your existing AEM 6.5 project for deployment via AMS Cloud Manager.

## Prerequisites

- AEM 6.5 project using Maven
- Multi-module project with an `all` module (standard AEM archetype structure)
- Java 11+
- Maven 3.3.9+

## Installation Methods

### Method 1: Maven Central (Recommended)

The easiest way to include Gradial OAuth in your project.

#### Step 1: Add Dependency

In your project's `all/pom.xml`, add the Gradial OAuth package as a dependency:

```xml
<dependencies>
    <!-- Existing dependencies -->

    <!-- Gradial OAuth Package -->
    <dependency>
        <groupId>io.github.gradial</groupId>
        <artifactId>gradial.all</artifactId>
        <version>1.1.0</version>
        <type>zip</type>
    </dependency>
</dependencies>
```

#### Step 2: Embed in Your Container Package

In the same `all/pom.xml`, configure the FileVault plugin to embed Gradial OAuth:

```xml
<plugin>
    <groupId>org.apache.jackrabbit</groupId>
    <artifactId>filevault-package-maven-plugin</artifactId>
    <configuration>
        <embeddeds>
            <!-- Your existing embedded packages -->

            <!-- Embed Gradial OAuth -->
            <embedded>
                <groupId>io.github.gradial</groupId>
                <artifactId>gradial.all</artifactId>
                <type>zip</type>
                <target>/apps/vendor-packages/gradial/install</target>
            </embedded>
        </embeddeds>
    </configuration>
</plugin>
```

#### Step 3: Build and Deploy

Build your project as usual:

```bash
mvn clean install
```

Deploy via AMS Cloud Manager or your standard deployment process. The Gradial OAuth package will be embedded in your container package and installed automatically.

---

### Method 2: Corporate Nexus/Artifactory

If your organization uses a corporate Maven repository manager (Nexus, Artifactory, etc.), you can install the Gradial package there.

#### Step 1: Download the Package

Download the latest release from GitHub:
- https://github.com/gradial/gradial-oauth/releases

#### Step 2: Install to Corporate Repository

**Using Nexus UI:**
1. Log in to Nexus
2. Navigate to your repository
3. Upload artifact:
   - **GroupId**: `io.github.gradial`
   - **ArtifactId**: `gradial.all`
   - **Version**: `1.1.0`
   - **Packaging**: `zip`
   - **File**: Upload the downloaded ZIP

**Using Maven Command Line:**
```bash
mvn deploy:deploy-file \
  -DgroupId=io.github.gradial \
  -DartifactId=gradial.all \
  -Dversion=1.1.0 \
  -Dpackaging=zip \
  -Dfile=gradial.all-1.1.0.zip \
  -DrepositoryId=your-nexus-releases \
  -Durl=https://nexus.yourcompany.com/repository/releases/
```

#### Step 3: Add Dependency and Embed

Follow the same steps as Method 1 (Steps 1-3). Maven will resolve the package from your corporate repository.
