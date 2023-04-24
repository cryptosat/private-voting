# Private Voting
This library implements an API for running privacy-preserving ballots. The library can be compiled to WASM, making it suitable for use within a browser application (for Cryptosim), as well as part of the flight software.

## Installing prerequisites
Prerequisites include
 
 *  `cargo`
 *  `wasm-pack`

`cargo` can be installed using `rustup`. Follow the installation instructions on [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

Once `cargo` is installed, `wasm-pack` can be installed by running

    $ cargo install wasm-pack

## Building and testing

To run the unit tests, execute
    
    $ cargo test

To build the WASM target and its JS bindings, run

    $ wasm-pack build --target web
    
The WASM target and JS bindings will then be placed in a `pkg` directory.

To test the library, use `html/test.html`, serving it using a local webserver (rather than opening the file directly which won't work due to CORS policies). You can run a simple Python HTTP server using:

    $ python3 -m http.server 8000
    
and then access [https://localhost:8000/html/test.html](https://localhost:8000/html/test.html) in your browser.

### Testing in a browser

To run unit tests in a browser, execute

    $ wasm-pack test --chrome

To test calling the compiled WASM from Javascript code, there is a simple HTML under the `html` directory, named `test.html`. It has to be served over HTTP and not just opened directly as a file in the browser, since otherwise, CORS policies will block importing the Javascript file with the WASM bindings.

### Generating documentation
To build the documentation for the `private_voting` library, execute

     $ cargo doc
     
which outputs the documentation in HTML format under `target/doc`.




## Build Instructions
To build this package, you will need to have wasm-pack installed on your machine.

Run the following command to build the package for both browser and Node.js environments:


```npm run build```
This command will execute the following scripts:

build:browser: Builds the package for browser environment using wasm-pack with the web target and outputs to ./build/browser directory. It then removes the package.json file in the ./build/browser directory using rimraf.


build:node: Builds the package for Node.js environment using wasm-pack with the nodejs target and outputs to ./build/node directory. It then removes the package.json file in the ./build/node directory using rimraf.


### Package Structure
The package includes the following files and directories:

build: The build output directory containing the compiled WASM modules for both browser and Node.js environments.
types: The TypeScript type definitions for the package.
exports: The package exports, including the browser and Node.js modules and the corresponding WASM binary files.



### Dependencies
This package has the following development dependency:

rimraf: A utility to remove files and directories. It is used to remove the package.json files generated by wasm-pack in the build output directories.



### Usage
After building the package, you can import and use it in your projects. The package supports both browser and Node.js environments. Below is an example of how to import and use the package:

```
import * as privateVoting from 'private_voting';

// Use the privateVoting module functions here...
```


## Publishing to npm
To publish the private_voting package on npm, follow these steps:

Make sure you have an npm account and you're logged in to your account using the npm CLI.

Ensure the package.json file is updated with the correct version number and other necessary information.

In the terminal or command prompt, navigate to the root directory of your package (where the package.json file is located).

Run the following command to publish the package:

```
npm publish
```
This command will package and publish your module to the npm registry.