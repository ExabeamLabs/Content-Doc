#### Parser Content
```Java
{
Name = cef-windows-dns-query-1
  DataType = "dns-query"
  Conditions = [ """ cat=PACKET """, """   Q [""" ]
  Fields = ${MicrosoftParserTemplates.cef-windows-dns-query-1.Fields}[
    """\s+\S+\s+({protocol}\S+)\s+({activity}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+\S+\s+Q\s+\[\S+\s+(\s|({query_flags}.+?))\s+\S+\]\s+({query_type}\S+)\s+({query}.+?)\s"""
  ]
}
cef-windows-dns-query-1 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
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