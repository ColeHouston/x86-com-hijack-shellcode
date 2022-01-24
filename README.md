# x86-com-hijack-shellcode
32 bit shellcode that performs COM hijacking with Chrome

## Usage: 
The shellcode will download a DLL from the URL "http://localhost/d.dll" and save it to "C:\Users\Public\d.dll". It then creates the registry key "HKCU\SOFTWARE\Classes\CLSID\{A4B544A1-438D-4B41-9325-869523E2D6C7}\InprocServer32", and sets the following values in it:
- (Default) = "C:\Users\Public\d.dll"
- ThreadingModel = "Apartment"

With these values set d.dll will be executed every time Google Chrome starts up, resulting in persistence on the system.

### Note:
The URLDownloadToFileA API is picky about the URLs supplied to it, and I could not get the API to work over HTTP with any sites I was accessing over WAN. However, HTTPS works just fine, so be sure to host the DLL on a URL over HTTPS if modifying the shellcode to download something over the internet.
