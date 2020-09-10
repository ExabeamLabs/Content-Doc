#### Parser Content
```Java
{
Name = raw-unix-dns-appliedadd
  Vendor = Unix
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " applied ADD for ", "IN A" ]
  Fields = [ """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """applied ADD for '({dest_host}[^']+).+? IN A ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```