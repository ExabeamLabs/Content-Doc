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
   """timestamp:({time}\d+.\d+.\d+ \d+:\d+:\d+)""",
   """({host}[^\s]+)\s+SecureTrack:""",
   """Login was done by\s+({user}[^,\s].+?)\.,""",
   ]  
}
```