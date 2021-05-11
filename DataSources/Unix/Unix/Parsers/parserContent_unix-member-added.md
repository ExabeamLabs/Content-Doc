#### Parser Content
```Java
{
Name = unix-member-added
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """][""", """ usermod """, """ add """, """ group """ ]
  Fields = [
    """\[({src_ip}[a-fA-F\d.:]+)\]\[\d{1,100}\]\[""",
    """<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d) ({host}[\w.\-]+) usermod""",
    """add '({account_name}[^']+)' to.+?group '({group_name}[^']+)'""",
  ]
  DupFields = [ "host->dest_host" ]
}
```