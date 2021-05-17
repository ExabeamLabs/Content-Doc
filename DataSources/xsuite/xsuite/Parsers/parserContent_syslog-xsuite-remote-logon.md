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
    """connection,({dest_host}[\w.-]{1,2000}),""",
    """({user_dn}CN\s{0,100}=\s{0,100}.+?)",connection,""",
    ""","?({user}[^=]{0,2000}[^"])"?,connection,""",
    """(exabeam_\w+=|^)({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s[^,=]{1,2000}),""",
  ]
}
```