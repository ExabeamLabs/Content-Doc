#### Parser Content
```Java
{
Name = syslog-xsuite-remote-logon
  Vendor = xsuite
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
```