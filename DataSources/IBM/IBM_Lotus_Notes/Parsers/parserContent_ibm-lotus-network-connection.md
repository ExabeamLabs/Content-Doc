#### Parser Content
```Java
{
Name = ibm-lotus-network-connection
  Vendor = IBM
  Product = IBM Lotus Notes
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""  SMTP Server: """, """ connected""", ]
  Fields = [
    """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """exabeam_host=({host}[\w.\-]+)""",
    """SMTP Server:\s*({dest_host}.+?) \(({dest_ip}[a-fA-F\d.:]+)\)""",
  ]
}
```