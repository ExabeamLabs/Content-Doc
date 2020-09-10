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
```