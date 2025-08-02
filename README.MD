# Ignition GAN Study

## How to create stubs ?

It looks like depending on the Ignition version you use (tested with 8.0X and 8.1X) the payload will change. To understand the classes, you need to take a look at their serialized data

![alt text](docs\diff_data.png)

Here for example the `com/inductiveautomation/metro/api/ServerId` is missing the `routePath` String

