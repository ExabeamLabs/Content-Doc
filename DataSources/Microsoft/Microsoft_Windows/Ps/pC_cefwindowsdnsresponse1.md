#### Parser Content
```Java
{
Name = cef-windows-dns-response-1
  DataType = "dns-response"
  Conditions = [ """cat=PACKET""", """ R Q [""" ]
  Fields = ${MicrosoftParserTemplates.cef-windows-dns-query-1.Fields}[
    """\s{1,100}({protocol}\S+)\s{1,100}({activity}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}\S+\s{1,100}(R)? (Q|U)\s{1,100}\[\S+\s{1,100}({response_flags}.+?)\s{1,100}({dns_response_code}\S+)\]\s{1,100}(NULL|({query_type}\S+))\s{1,100}({query}.+?)\s"""
  ]
}
cef-windows-dns-query-1 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\srt=({time}\d{10})""",
    """\scs4=({dns_response_code}[^\s]{1,2000})\s""",
    """\srequest=({query}[^\s]{1,2000})\s""",
    """\sdst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """\sdhost=({dest_host}[^\s]{1,2000})\s""",
    """\sshost=({src_host}[^\s]{1,2000})\s""",
    """\sproto=({protocol}[^\s]{1,2000})\s""",
    """\scs2=({event_code}.+)\scs3=""",
    """\scs3=({query_flags}.+)\scs4=""",
    """\sdvc=({host}[\w\-.]{1,2000})\s""",
    """\sdvchost=({host}[\w\-.]{1,2000})\s""",
  ]

```