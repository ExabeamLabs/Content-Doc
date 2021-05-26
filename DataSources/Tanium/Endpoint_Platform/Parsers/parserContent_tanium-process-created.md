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
      """({host}[\w.\-]{1,2000})\s{1,100}Tanium """,
      """\sEndpoint-Name="(-|({dest_host}[\w.\-]{1,2000}))"""",
      """\sStart-Time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
      """\sUsername="(-|({user}[^"]{1,2000}))"""",
      """\sDomain="(-|({domain}[^"]{1,2000}))"""",
      """\sMD5="(-|({md5}[^"]{1,2000}))"""",
      """\sCommand-Line="(-|({command_line}[^"]{1,2000}))"""",
      """\sParent-Process-Path="(-|<Unknown Process>|({parent_process}({parent_process_directory}[^"]{0,2000}?[\\\/]{1,2000})?({parent_process_name}[^"\\\/]{1,2000})))"""",
      """\sProcess-Path="(-|({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000})))"""",
    ]
  }
```