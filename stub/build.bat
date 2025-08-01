rm -rf out
rm -rf metro-stub.jar
mkdir out
"C:\Program Files\OpenJDK\jdk-16\bin\javac.exe" -d out src\com\inductiveautomation\metro\api\*.java src\com\inductiveautomation\metro\utils\*.java src\com\inductiveautomation\metro\impl\transport\*.java
"C:\Program Files\OpenJDK\jdk-16\bin\jar.exe" cf metro-stub.jar -C out .
jython -J-cp metro-stub.jar

import sys
sys.path.append("./metro-stub.jar")

