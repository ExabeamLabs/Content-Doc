#### Parser Content
```Java
{
Name = syslog-l7-remote-logon
  Vendor = Kemp
  Product = Kemp LoadMaster
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ """ l7log:""", """ logged on from """ ]
  Fields = [
    """exabeam_host=({host}[\w\.\-]{1,2000})""",
    """\s({host}[\w\.\-]{1,2000})\s{1,100}\S+\s{1,100}\S+\s{1,100}l7log:""",
    """l7log:\s{1,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s:]{1,2000}))""",
    """from\s{1,100}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s:]{1,2000}))""",
    """\sUser\s{1,100}({user}.+?)\s{1,100}logged""",
  ]
}
```