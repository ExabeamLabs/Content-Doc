#### Parser Content
```Java
{
Name = extrahop-4769
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4769"
  TimeFormat = "epoch"
  Conditions = [ """"event_code":4769""", """"constrained-delegation":""", """"disable-transited-check":""", """"enc-tkt-in-skey":""" ]
  Fields = [
    """"host":"(::1|({host}[a-fA-F:\d.]+))""",
    """"src_ip":"(::1|({src_ip}[a-fA-F:\d.]+))""",
    """"dest_host":"({service_name}[^"]+)""",
    """"time":({time}\d{13})""",
    """"result_code":"({result_code}[^"]+)""",
    """"user":(null|"({user}[^"]+))""",
    """"user":(null|"({user_email}({user}[^"@]+)@[^"]+))""",
    """"domain":"({domain}[^"]+)""",
    """"event_code":({event_code}\d+)""",
  ]
  DupFields = [ "service_name->dest_host" ]
}
```