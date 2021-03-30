#### Parser Content
```Java
{
Name = unix-auth-failed-5
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """authentication failure;""","""logname=""","""ruser""" ]
  Fields = [
    """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S+\s+({host}[^\s]+)\s+({process_name}[^\s]+)\s+({process_id}\d+)\s""",
    """ruser=({user}[^\s]+)""",
    """rhost=({src_ip}[\da-fA-F.:]+)""",
    """authentication ({outcome}failure)""",
  ]
}
```