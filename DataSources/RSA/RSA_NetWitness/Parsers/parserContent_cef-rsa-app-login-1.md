#### Parser Content
```Java
{
Name = cef-rsa-app-login-1
 Product = RSA NetWitness
 Vendor = RSA
 TimeFormat = "MMM dd yyyy HH:mm:ss"
 DataType = "app-login"
 Lms = Direct
 Conditions = ["""CEF:""", """RSA|NetWitness Audit""", """|AUTHENTICATION|login|""", """outcome=success"""]
 Fields = [
   """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
   """rt=({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
   """src=(127.0.0.1|({src_ip}[A-Fa-f.:\d]{1,2000}))""",
   """spt=({src_port}\d{1,100})""",
   """sessionId=({session_id}\d{1,100})""",
   """({app}NetWitness)""",
   """\Wsuser=((?i)system|({user}[^=\(]{1,2000}))(\s\w+=|\()""",
   """sourceServiceName=({service_name}[^=]{1,2000}?)\s\w+=""",
   """outcome=({outcome}[^=]{1,2000}?)\s\w+=""",
   """userRole=({role}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
   """CEF:\d{1,100}\|([^\|]{1,2000}\|){4}({event_name}[^\|]{1,2000})"""
   ]
}
```