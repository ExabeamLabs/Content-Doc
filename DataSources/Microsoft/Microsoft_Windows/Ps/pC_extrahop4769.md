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
    """"host":"(::1|({host}[a-fA-F:\d.]{1,2000}))""",
    """"src_ip":"(::1|({src_ip}[a-fA-F:\d.]{1,2000}))""",
    """"dest_host":"({service_name}[^"]{1,2000})""",
    """"time":({time}\d{13})""",
    """"result_code":"({result_code}[^"]{1,2000})""",
    """"user":(null|"({user}[^"]{1,2000}))""",
    """"user":(null|"({user_email}({user}[^"@]{1,2000})@[^"]{1,2000}))""",
    """"domain":"({domain}[^"]{1,2000})""",
    """"event_code":({event_code}\d{1,100})""",
  ]
  DupFields = [ "service_name->dest_host" ]


}
```