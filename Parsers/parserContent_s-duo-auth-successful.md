#### Parser Content
```Java
{
Name = s-duo-auth-successful
  Vendor = Duo Security
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Duo authentication returned 'allow'""","""Success"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\]\s+\(\(\'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\]\s+\(\(\'.+?\',\s*({session_id}\d+)\)""" ]
}
```