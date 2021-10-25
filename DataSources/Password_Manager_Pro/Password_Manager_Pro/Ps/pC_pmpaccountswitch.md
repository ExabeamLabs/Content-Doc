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
    """\s{1,100}({user}({user_firstname}[^\s:_]{1,2000})(_({user_lastname}[^:\s]{1,2000}))?):(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]{1,2000}))\s{1,100}Password_Retrieved""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sSuccess\s[^\s]{1,2000}\s{1,100}({safe_value}[^:]{1,2000}):({account}[^:]{1,2000}):""",
  ]
}
```