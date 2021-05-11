#### Parser Content
```Java
{
Name = pmp-password-change
  Vendor = Password Manager Pro
  Product = Password Manager Pro
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [  """ Password_Changed """,""" Success """ ]
  Fields = [
    """\s{1,100}({user}({user_firstname}[^\s:_]+)(_({user_lastname}[^:\s]+))?):(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+))\s{1,100}Password_Changed""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)""",
    """\sSuccess\s[^\s]+\s{1,100}({safe_value}[^:]+):({target_user}[^:]+):""",
  ]
}
```