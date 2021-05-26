#### Parser Content
```Java
{
Name = unix-password-change
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """][""", """ usermod """, """ change user """, """ password """ ]
  Fields = [
    """\[({src_ip}[a-fA-F\d.:]{1,2000})\]\[\d{1,100}\]\[""",
    """<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d) ({host}[\w.\-]{1,2000}) usermod""",
    """change user '({account_name}[^']{1,2000})' password"""
  ]
  DupFields = [ "host->dest_host" ]
}
```