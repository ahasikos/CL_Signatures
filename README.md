# Repository that implements the schemes for the paper Signature Schemes and Anonymous Credentials from Bilinear Maps

## Disclaimer
This is a personal project. Avoid using this library in production as it has not been audited.

## Dependencies
[miracl/core](https://github.com/miracl/core): Building instructions can be found in the official repo

## Building
This project requires the **core** library built with the BN254 Curve

```asm
cmake -DCORE_LIB_PATH=<PATH_TO_CORE_LIBRARY> ..
make all
```

## Testing
After building there will be two executables

1. `test_anonymous_credentials`
2. `test_cl_signatures`