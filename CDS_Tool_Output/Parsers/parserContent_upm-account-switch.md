#### Parser Content
```Java
{
Name = upm-account-switch
  Vendor = Unix
  Product = Unix Privilege Management
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "epoch_sec"
  Conditions = [ """ upm-log end=""", """: accepted su""" ]
  Fields = [
    """({host}[\w\.\-]+)\s+upm-log end=({time}\d+)""",
    """: accepted su \S+\s+({account}[^\s]+)""",
    """ from ({user}[^@\s]+)@(eth0\.)?({src_host}[^@\s]+)""",
    """ to ({account}[^@\s]+)@(eth0\.)?({dest_host}[^@\s]+)""",
  ]
}
```