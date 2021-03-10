#### Parser Content
```Java
{
Name = pmp-password-change
  Vendor = Password Manager Pro
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [  """ Password_Changed """,""" Success """ ]
  Fields = [
    """\s+({user}({user_firstname}[^\s:_]+)(_({user_lastname}[^:\s]+))?):(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]+))\s+Password_Changed""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d\s+({host}[^\s]+)""",
    """\sSuccess\s[^\s]+\s+({safe_value}[^:]+):({target_user}[^:]+):""",
  ]
}
```