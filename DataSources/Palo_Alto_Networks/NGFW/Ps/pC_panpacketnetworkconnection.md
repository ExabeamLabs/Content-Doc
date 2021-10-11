#### Parser Content
```Java
{
Name = pan-packet-network-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,packet,""", """,client""", """,,""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\d{1,100},""",
    """,({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}),({src_ip}[A-Fa-f:\d.]{1,2000}),({dest_ip}[A-Fa-f:\d.]{1,2000}),""",
    """,\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100},\d{1,100},\d{1,100},({src_port}\d{1,100}),({dest_port}\d{1,100}),\d{0,100},\d{0,100},\w*,({protocol}[^\s,]{1,2000}),({outcome}[^,]{1,2000}),[^,]{0,2000},({additional_info}[^,]{1,2000}),[^,]{0,2000},({severity}[^,]{0,2000}),({direction}[^,]{0,2000}),""",
  ]
  DupFields = [ "outcome->action" ]
}
```