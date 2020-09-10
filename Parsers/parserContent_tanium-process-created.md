#### Parser Content
```Java
{
Name = tanium-process-created
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Direct
    DataType = "process-created"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ """ Tanium """, """Question="Exabeam-Process-Creations-Test"""", """ Start-Time="2""" ]
    Fields = [
      """({host}[\w.\-]+)\s+Tanium """,
      """\sEndpoint-Name="(-|({dest_host}[\w.\-]+))"""",
      """\sStart-Time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)""",
      """\sUsername="(-|({user}[^"]+))"""",
      """\sDomain="(-|({domain}[^"]+))"""",
      """\sMD5="(-|({md5}[^"]+))"""",
      """\sCommand-Line="(-|({command_line}[^"]+))"""",
      """\sParent-Process-Path="(-|<Unknown Process>|({parent_process}({parent_process_directory}[^"]*?[\\\/]+)?({parent_process_name}[^"\\\/]+)))"""",
      """\sProcess-Path="(-|({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+)))"""",
    ]
  }
```