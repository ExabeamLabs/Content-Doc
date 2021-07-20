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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """SMTP Server:\s{0,100}({dest_host}.+?) \(({dest_ip}[a-fA-F\d.:]{1,2000})\)""",
  ]
}
```