# Service Provider Interfaces

A Service Provider Interface (SPI) is a contract that lets a framework or
application use an implementation supplied separately. The code that uses
the service can depend on the contract while providers supply the behavior.

| Role | Example |
| --- | --- |
| Service contract | A `Greeting` interface defines a `message()` method. |
| Service provider | An `EnglishGreeting` class implements the interface. |
| Discovery or selection | An application loads a registered implementation or explicitly selects one. |
| Service consumer | Application code calls `message()` through the interface. |

## A Java classpath example

The contract and provider belong in separate Java source files:

```java
// example/spi/Greeting.java
package example.spi;

public interface Greeting {
    String message();
}
```

```java
// example/english/EnglishGreeting.java
package example.english;

import example.spi.Greeting;

public final class EnglishGreeting implements Greeting {
    @Override
    public String message() {
        return "Hello";
    }
}
```

The provider JAR includes a text file named
`META-INF/services/example.spi.Greeting` with this line:

```text
example.english.EnglishGreeting
```

On a classpath containing both the contract and provider, the consumer can
discover an implementation with `ServiceLoader`:

```java
Greeting greeting = ServiceLoader.load(Greeting.class).findFirst().orElseThrow();
System.out.println(greeting.message());
```

`findFirst()` is enough for the example with a single provider. When several
providers are available and the choice matters, the consumer needs an explicit
selection rule. Named Java modules can declare `uses` and `provides … with`
in `module-info.java`.

## Where the contract appears in this project

`TextEncryption` is the project-level contract. Callers can use
`JdkTextEncryption` or `BouncyCastleTextEncryption` through that interface.
The tests construct each implementation explicitly. Inside those implementations,
Java's cryptographic framework uses [its own provider SPI](jce-spi.md).

[Java 25 ServiceLoader documentation](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/util/ServiceLoader.html)
