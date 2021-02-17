#### Parser Content
```Java
{
Name = raw-4742
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """A computer account was changed""", """4742""" ]
  Fields = [
    """({event_name}A computer account was changed)""",
    """exabeam_host=([^=]+?@\s*)?(::ffff:)?({host}[\w.-]+)""",
    """<Computer>(::ffff:)?({host}[^<]+)</Computer>""",
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+)""",
    """\w+\s*\d+\s\d+:\d+:\d+\s+(::ffff:)?({host}[\w\-.]+)""",
    """({event_code}4742)""",
    """Subject:.+?\sAccount Name:\s*(|-|({user}.+?))\s*Account Domain:\s*(|-|({domain}.+?))\s*Logon ID:\s*(|-|({logon_id}.+?))\s*Computer Account That Was Changed:.*?\sAccount Name:\s*(|-|({target_user}.+?))\s*Account Domain:\s*(|-|({object_dn}.+?))\s*Changed Attributes:""",
    """\sComputer Account That Was Changed:.+?Account Name:\s*(::ffff:)?({src_host}[^$:]+?)\$""",
    """\sUser Principal Name:\s*(|-|({attribute}.+?))\s*Home Directory:""",
    """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
  ]
}
```