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
   """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
   """rt=({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
   """src=(127.0.0.1|({src_ip}[A-Fa-f.:\d]+))""",
   """spt=({src_port}\d{1,100})""",
   """sessionId=({session_id}\d{1,100})""",
   """({app}NetWitness)""",
   """\Wsuser=((?i)system|({user}[^=\(]+))(\s\w+=|\()""",
   """sourceServiceName=({service_name}[^=]+?)\s\w+=""",
   """outcome=({outcome}[^=]+?)\s\w+=""",
   """userRole=({role}[^=]+?)\s{0,100}(\w+=|$)""",
   """CEF:\d{1,100}\|([^\|]+\|){4}({event_name}[^\|]+)"""
   ]
}
```