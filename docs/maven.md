![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# Accessing Libraries from Maven Central


All libraries for the credentials-support project is published to Maven central.

Include the following snippets in your Maven POM to add dependencies for your project.

The **credentials-support** base library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

The **credentials-support-opensaml** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-opensaml</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include the **opensaml-library**.

The **credentials-support-nimbus** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-nimbus</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include the **opensaml-library**.

The **credentials-support-spring** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-spring</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include the **opensaml-library**.

The **credentials-support-spring-boot-starter** library:

```
<dependency>
  <groupId>se.swedenconnect.security</groupId>
  <artifactId>credentials-support-spring-boot-starter</artifactId>
  <version>${credentials-support.version}</version>
</dependency>
```

> Will include **opensaml-library** and **credentials-support-spring**.

---

Copyright &copy; 2020-2024, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).