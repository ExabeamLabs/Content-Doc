#### Parser Content
```Java
{
Name = secure-system-login
 Product = SecureTrack
 Vendor = Tufin
 Lms = Direct
 TimeFormat = "yyyy.MM.dd HH:mm:ss.SSS"
 DataType = "authentication-successful"
 Conditions = [ """ELM""", """SecureTrack:"""]
 Fields =[
   """timestamp:({time}\d{1,100}.\d{1,100}.\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
   """({host}[^\s]{1,2000})\s{1,100}SecureTrack:""",
   """Login was done by\s{1,100}({user}[^,\s].+?)\.,""",
   ]  
}
```