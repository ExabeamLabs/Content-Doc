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
    """({host}[\w\.\-]{1,2000})\s{1,100}upm-log end=({time}\d{1,100})""",
    """: accepted su \S+\s{1,100}({account}[^\s]{1,2000})""",
    """ from ({user}[^@\s]{1,2000})@(eth0\.)?({src_host}[^@\s]{1,2000})""",
    """ to ({account}[^@\s]{1,2000})@(eth0\.)?({dest_host}[^@\s]{1,2000})""",
  ]
}
```