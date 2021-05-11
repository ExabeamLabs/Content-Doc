#### Parser Content
```Java
{
Name = extrahop-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "epoch"
  Conditions = [ """"event_code":4770""", """"constrained-delegation":""", """"disable-transited-check":""", """"enc-tkt-in-skey":""" ]
  Fields = [
    """"time":({time}\d{13})""",
    """"host":"(::1|({host}[a-fA-F:\d.]+))""",
    """"src_ip":"(::1|({src_ip}[a-fA-F:\d.]+))""",
    """"result_code":"({result_code}[^"]+)""",
    """"user":(null|"({user}[^"]+))""",
    """"user":(null|"({user_email}({user}[^"@]+)@[^"]+))""",
    """"domain":"({domain}[^"]+)""",
    """"event_code":({event_code}\d{1,100})""",
    """"dest_ip":"(::1|({dest_ip}[a-fA-F:\d.]+))""",
  ]
}
```