#### Parser Content
```Java
{
Name = raw-unix-dhcp-forwardmap
  Vendor = Unix
  Product = Unix dhcpd
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Added new forward map from """ ]
  Fields = [ 
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """Added new forward map from ({dest_host}[\w\-.]{1,2000})\sto\s({dest_ip}[A-Fa-f\d:.]{1,2000})"""
  ]


}
```