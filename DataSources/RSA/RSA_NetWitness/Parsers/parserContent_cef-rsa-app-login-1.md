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
   """exabeam_host=([^=]+@\s*)?({host}\S+)""",
   """rt=({time}\w+ \d+ \d+ \d+:\d+:\d+)""",
   """src=(127.0.0.1|({src_ip}[A-Fa-f.:\d]+))""",
   """spt=({src_port}\d+)""",
   """sessionId=({session_id}\d+)""",
   """({app}NetWitness)""",
   """\Wsuser=((?i)system|({user}[^=\(]+))(\s\w+=|\()""",
   """sourceServiceName=({service_name}[^=]+?)\s\w+=""",
   """outcome=({outcome}[^=]+?)\s\w+=""",
   """userRole=({role}[^=]+?)\s*(\w+=|$)""",
   """CEF:\d+\|([^\|]+\|){4}({event_name}[^\|]+)"""
   ]
}
```