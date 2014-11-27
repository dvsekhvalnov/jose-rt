tools\nuget.exe update -self

if not exist JoseRT\bin\Release\nupkg mkdir JoseRT\bin\Release\nupkg
if not exist JoseRT\bin\Release\nupkg\content mkdir JoseRT\bin\Release\nupkg\content
if not exist "JoseRT\bin\Release\nupkg\lib\portable-wpa8.1+win8.1" mkdir "JoseRT\bin\Release\nupkg\lib\portable-wpa8.1+win8.1"

copy JoseRT\bin\Release\JoseRT.winmd "JoseRT\bin\Release\nupkg\lib\portable-wpa8.1+win8.1"
copy LICENSE JoseRT\bin\Release\nupkg\content

tools\nuget.exe pack jose-rt.nuspec -BasePath JoseRT\bin\Release\nupkg