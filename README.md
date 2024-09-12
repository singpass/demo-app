## Getting started

Prerequisites:
- We have completed Step 1 in the [Onboarding checklist](https://docs.developer.singpass.gov.sg/singpass-developer-docs/getting-started/onboarding-checklist)
to register and configure the demo app.

1. Starting the demo app in your preferred language:

   1. **NodeJS**
      
      Install [NodeJS and npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) and run
      ```shell
      cd examples/nodejs
      npm install
      npm start
      ```

   2. **Java**
      
      Install [JDK](https://docs.oracle.com/en/java/javase/17/install/overview-jdk-installation.html) and run
      ```shell
      cd examples/java
      ./gradlew bootRun
      ```

2. In your browser click on Log in with Singpass. (http://localhost:3080)

![before login screenshot](docs/before-login.png)

3. After successfully login, you should see a user ID returned from Singpass API.
 
![after login screenshot](docs/after-login.png)
