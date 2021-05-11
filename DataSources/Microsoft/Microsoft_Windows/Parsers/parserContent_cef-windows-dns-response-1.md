#### Parser Content
```Java
{
Name = cef-windows-dns-response-1
  DataType = "dns-response"
  Conditions = [ """cat=PACKET""", """ R Q [""" ]
  Fields = ${MicrosoftParserTemplates.cef-windows-dns-query-1.Fields}[
    """\s{1,100}({protocol}\S+)\s{1,100}({activity}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]+)\s{1,100}\S+\s{1,100}(R)? (Q|U)\s{1,100}\[\S+\s{1,100}({response_flags}.+?)\s{1,100}({dns_response_code}\S+)\]\s{1,100}(NULL|({query_type}\S+))\s{1,100}({query}.+?)\s"""
  ]
}
cef-windows-dns-query-1 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """\srt=({time}\d{10})""",
    """\scs4=({dns_response_code}[^\s]+)\s""",
    """\srequest=({query}[^\s]+)\s""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """\sdhost=({dest_host}[^\s]+)\s""",
    """\sshost=({src_host}[^\s]+)\s""",
    """\sproto=({protocol}[^\s]+)\s""",
    """\scs2=({event_code}.+)\scs3=""",
    """\scs3=({query_flags}.+)\scs4=""",
    """\sdvc=({host}[\w\-.]+)\s""",
    """\sdvchost=({host}[\w\-.]+)\s""",
  ]

```