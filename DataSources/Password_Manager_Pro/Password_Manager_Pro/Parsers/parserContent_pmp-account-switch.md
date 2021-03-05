#### Parser Content
```Java
{
Name = pmp-account-switch
  Vendor = Password Manager Pro
  Product = Password Manager Pro
  Lms = Splunk
  DataType = "account-switch"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [  """ Password_Retrieved """,""" Success """ ]
  Fields = [
    """\s+({user}({user_firstname}[^\s:_]+)(_({user_lastname}[^:\s]+))?):(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+))\s+Password_Retrieved""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d\s+({host}[^\s]+)""",
    """\w+ \d+ \d\d:\d\d:\d\d\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sSuccess\s[^\s]+\s+({safe_value}[^:]+):({account}[^:]+):""",
  ]
}
```