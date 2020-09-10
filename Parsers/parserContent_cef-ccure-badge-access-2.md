#### Parser Content
```Java
{
Name = cef-ccure-badge-access-2
    Vendor = CCURE
    Product = CCURE
    Lms = ArcSight
    DataType = "physical-access"
    TimeFormat = "epoch"
    Conditions = ["""CEF:""", """|Software House|CCure Badge|"""]
    Fields = [
      """\srt=({time}\d+)""",
      """\sduser=\s*({last_name}[^,]+?)\s*,\s*({first_name}.+?)(\s+\w+=|\s*$)""",
      """\scs3=({location_door}.+?)(\s+\w+=|\s*$)""",
      """\|CCure Badge\|[^\|]*\|({outcome}.+?)\|"""
      """exabeam_host=({host}[\w.\-]+)""",
    ]
  }

  {
    Name = tanium-auth
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Direct
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ """ Tanium """, """Question="Exabeam-Logon-Even-Test"""" ]
    Fields = [
      """({host}[\w.\-]+)\s+Tanium """,
      """\sEndpoint-Name="(-|({dest_host}[^"]+))"""",
      """\sTimestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)""",
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