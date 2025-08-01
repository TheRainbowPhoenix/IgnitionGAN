Remove-Item -Recurse -Force out -ErrorAction SilentlyContinue
New-Item -ItemType Directory out

$sources = Get-ChildItem -Recurse -Filter *.java -Path src | ForEach-Object { $_.FullName }
& "C:\Program Files\OpenJDK\jdk-16\bin\javac.exe" -d out $sources

& "C:\Program Files\OpenJDK\jdk-16\bin\jar.exe" cf metro-stub.jar -C out .