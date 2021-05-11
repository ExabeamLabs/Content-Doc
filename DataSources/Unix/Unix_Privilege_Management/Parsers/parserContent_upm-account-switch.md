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
    """({host}[\w\.\-]+)\s{1,100}upm-log end=({time}\d{1,100})""",
    """: accepted su \S+\s{1,100}({account}[^\s]+)""",
    """ from ({user}[^@\s]+)@(eth0\.)?({src_host}[^@\s]+)""",
    """ to ({account}[^@\s]+)@(eth0\.)?({dest_host}[^@\s]+)""",
  ]
}
```