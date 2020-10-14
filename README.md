# Mirror

Burp Extension to help find reflected parameter vulnerabilities

## Burp Extension

The [Burp Suite](https://portswigger.net/burp) extension works in both the Community (Free) and Professional versions.

## Features:

- Passively scan for reflected parameters
- Local API server to inject JavaScript and inspect DOM for reflects parameters

## ToDo

- [ ] Mirror API for POST requests


## Install the Mirror Burp Suite Extension

### Download or build the extension

#### Option 1: Download release

You can find the latest release (JAR file) [here](https://github.com/TypeError/mirror/releases).

#### Option 2: Build the extension

```sh
gradle build fatJar
```

Extension JAR will be located at: `build/libs/mirror-x.x.jar`

### Load the extension

1. Open Burp Suite
2. Go to Extender tab
3. Burp Extensions -> Add
4. Load mirror-x.x.jar

### Usage

#### Passive scanning

1. Set scope
2. Manually navigate or spider the application
3. Requests with reflected parameters be added to the `Mirror` tab.

#### [Optional] Mirror API/DOM Inspection

1. Set scope
2. Start Mirror server
2. Manually navigate application with browser
3. Requests with reflected parameters be added to the `Mirror` tab.

Note: The Mirror API when on (and `Inject Mirror server JavaScript` checkbox is checked) will inject JavaScript into each GET request that is in scope. 
