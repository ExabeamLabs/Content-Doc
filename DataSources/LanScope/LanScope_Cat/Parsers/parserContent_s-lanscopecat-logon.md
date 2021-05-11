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
    """\sEvent="({activity}[^"]+)""",
    """\sAgent="({dest_host}[^"]+)""",
    """\sLogonUser="({user}[^"]+)""",
    """\sDomain="({domain}[^"]+)""",
    """\sStatus="({status}[^"]+)""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```