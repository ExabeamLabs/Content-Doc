#### Parser Content
```Java
{
Name = safeword-auth-successful
  Vendor = Secure Computing
  Product = Secure Computing SafeWord
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|SecureComputing|SafeWord PremierAccess|""","""categoryBehavior=/Authentication/Verify"""]
  Fields = [ """\srt=({time}\d{1,100})""",
    """cs4=\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}.\d{1,100} \(\w+\) ({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```