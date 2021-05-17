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
      """({host}[\w.\-]{1,2000})\s{1,100}Tanium """,
      """\sEndpoint-Name="(-|({src_host}[\w.\-]{1,2000}))"""",
      """\sTime-\(UTC\)="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
      """\sUsername="(-|({user}[^"]{1,2000}))"""",
      """\sQuery="(-|({query}[^"]{1,2000}))"""",
      """\sOperation="(-|({activity}[^"]{1,2000}))"""",
      """\sProcess-Name="(-|({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000})))"""",
      """\sResponse="(\[unresolved\]|(::ffff:)?({dest_ip}[a-fA-F\d.:]{1,2000}))"""",
    ]
  }
```