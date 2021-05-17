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
      """({host}[\w.\-]{1,2000})\s{1,100}Tanium """,
      """\sEndpoint-Name="(-|({dest_host}[^"]{1,2000}))"""",
      """\sTimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
      """\sTarget-User="(-|({user}[^"]{1,2000}))"""",
      """\sTarget-Domain="(-|({domain}[^"]{1,2000}))"""",
      """\sLogon-Result="(-|({outcome}[^"]{1,2000}))"""",
      """\sLogon-Type="(-|({logon_type}[^"]{1,2000}))"""",
      """\sLogon-Provider="(-|({auth_method}[^"]{1,2000}))"""",
      """\sProcess="(-|({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000})))"""",
      """\sSource-IP-Address="(::1|({src_ip}[a-fA-F\d.:]{1,2000}))"""",
    ]
  }
```