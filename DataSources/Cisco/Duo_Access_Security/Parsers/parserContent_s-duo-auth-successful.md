#### Parser Content
```Java
{
Name = s-duo-auth-successful
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Duo authentication returned 'allow'""","""Success"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\]\s{1,100}\(\(\'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\]\s{1,100}\(\(\'.+?\',\s{0,100}({session_id}\d{1,100})\)""" ]
}
```