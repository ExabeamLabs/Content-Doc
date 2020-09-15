#### Parser Content
```Java
{
Name = syslog-xsuite-remote-logon
  Vendor = xsuite
  Product = xsuite
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """xsuite[""", """,connection,""", """ connected """ ]
  Fields = [
    """connected\sto\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})[:;]""",
    """connection,({dest_host}[\w.-]+),""",
    """({user_dn}CN\s*=\s*.+?)",connection,""",
    ""","?({user}[^=]*[^"])"?,connection,""",
    """(exabeam_\w+=|^)({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s[^,=]+),""",
  ]
}

{
  Name = syslog-l7-remote-logon
  Vendor = Kemp
  Product = Kemp LoadMaster
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ """ l7log:""", """ logged on from """ ]
  Fields = [
    """exabeam_host=({host}[\w\.\-]+)""",
    """\s({host}[\w\.\-]+)\s+\S+\s+\S+\s+l7log:""",
    """l7log:\s+(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s:]+))""",
    """from\s+(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s:]+))""",
    """\sUser\s+({user}.+?)\s+logged""",
  ]
}
```