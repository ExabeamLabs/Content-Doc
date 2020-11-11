#### Parser Content
```Java
{
Name = safeword-auth-successful
  Vendor = Secure Computing
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|SecureComputing|SafeWord PremierAccess|""","""categoryBehavior=/Authentication/Verify"""]
  Fields = [ """\srt=({time}\d+)""",
    """cs4=\d+/\d+/\d+ \d+:\d+:\d+.\d+ \(\w+\) ({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\sshost=({src_host}[^\s]+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```