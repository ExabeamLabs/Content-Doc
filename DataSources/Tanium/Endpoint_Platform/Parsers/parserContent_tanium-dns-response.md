#### Parser Content
```Java
{
Name = tanium-dns-response
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Direct
    DataType = "dns-response"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ """ Tanium """, """Question="Exabeam-DNS-Connect-Test"""", """ Time-(UTC)="2""" ]
    Fields = [
      """({host}[\w.\-]+)\s+Tanium """,
      """\sEndpoint-Name="(-|({src_host}[\w.\-]+))"""",
      """\sTime-\(UTC\)="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)""",
      """\sUsername="(-|({user}[^"]+))"""",
      """\sQuery="(-|({query}[^"]+))"""",
      """\sOperation="(-|({activity}[^"]+))"""",
      """\sProcess-Name="(-|({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+)))"""",
      """\sResponse="(\[unresolved\]|(::ffff:)?({dest_ip}[a-fA-F\d.:]+))"""",
    ]
  }
```