#### Parser Content
```Java
{
Name = tanium-auth
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Direct
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ """ Tanium """, """Question="Exabeam-Logon-Even-Test"""" ]
    Fields = [
      """({host}[\w.\-]+)\s{1,100}Tanium """,
      """\sEndpoint-Name="(-|({dest_host}[^"]+))"""",
      """\sTimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
      """\sTarget-User="(-|({user}[^"]+))"""",
      """\sTarget-Domain="(-|({domain}[^"]+))"""",
      """\sLogon-Result="(-|({outcome}[^"]+))"""",
      """\sLogon-Type="(-|({logon_type}[^"]+))"""",
      """\sLogon-Provider="(-|({auth_method}[^"]+))"""",
      """\sProcess="(-|({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+)))"""",
      """\sSource-IP-Address="(::1|({src_ip}[a-fA-F\d.:]+))"""",
    ]
  }
```