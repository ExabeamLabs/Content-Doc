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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)\s+({host}\S+)\s+LanScopeCat\s+\-""",
    """\sEvent="({activity}[^"]+)""",
    """\sAgent="({dest_host}[^"]+)""",
    """\sLogonUser="({user}[^"]+)""",
    """\sDomain="({domain}[^"]+)""",
    """\sStatus="({status}[^"]+)""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```