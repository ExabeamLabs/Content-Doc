#### Parser Content
```Java
{
Name = s-lanscopecat-logon
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "local-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """LanScopeCat - LogonUserOn/Off""", """Status=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}LanScopeCat\s{1,100}\-""",
    """\sEvent="({activity}[^"]{1,2000})""",
    """\sAgent="({dest_host}[^"]{1,2000})""",
    """\sLogonUser="({user}[^"]{1,2000})""",
    """\sDomain="({domain}[^"]{1,2000})""",
    """\sStatus="({status}[^"]{1,2000})""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]{1,2000})""",
  ]
}
```