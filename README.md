## Getting started

Prerequisites:
- We have completed Step 1 in the [Onboarding checklist](https://docs.developer.singpass.gov.sg/singpass-developer-docs/getting-started/onboarding-checklist)
to register and configure the demo app.

Starting the demo app:
1. Install [NodeJS and npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).

2. Start the web client located in `examples/frontend`
    ```shell
    cd examples/frontend
    npm install
    npm start
    ```
3. Start the backend service in your preferred language:
   1. NodeJS
       ```shell
       cd examples/nodejs
       npm install
       npm start
       ```
   2. Java (coming soon)

4. In your browser click on Log in with Singpass

![before login screenshot](docs/before-login.png)

5. After successfully login, you should see a claims set returned from Singpass API.
 
![after login screenshot](docs/after-login.png)
