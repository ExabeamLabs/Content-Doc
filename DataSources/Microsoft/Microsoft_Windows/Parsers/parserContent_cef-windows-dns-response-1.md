#### Parser Content
```Java
{
Name = cef-windows-dns-response-1
  DataType = "dns-response"
  Conditions = [ """cat=PACKET""", """ R Q [""" ]
  Fields = ${MicrosoftParserTemplates.cef-windows-dns-query-1.Fields}[
    """\s+({protocol}\S+)\s+({activity}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+\S+\s+(R)? (Q|U)\s+\[\S+\s+({response_flags}.+?)\s+({dns_response_code}\S+)\]\s+(NULL|({query_type}\S+))\s+({query}.+?)\s"""
  ]
}
```