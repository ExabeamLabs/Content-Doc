#### Parser Content
```Java
{
Name = raw-unix-dhcp-forwardmap
  Vendor = Unix
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Added new forward map from " ]
  Fields = [ """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """Added new forward map from ({dest_host}.+?) to ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```