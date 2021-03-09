#### Parser Content
```Java
{
Name = windows-dns-response-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "dd/MM/yyyy HH:mm:ss"
  Conditions = [ """ PACKET """, """ R Q [""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({time}\d+\/\d+\/\d\d\d\d \d{1,2}:\d{1,2}:\d{1,2}((\+|\-)\d\d:\d\d)? (am|AM|pm|PM))\s+\S+\s+PACKET\s+\S+\s+({protocol}\S+)\s+({activity}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+\S+\s+(R)? (Q|U)\s+\[\S+\s+({response_flags}.+?)\s+({dns_response_code}\S+)\]\s+({query_type}\S+)\s+({query}.+?)\s""",
    """<Identifier>\S+\s+({host}\S+?)<\/Identifier>"""
    """({time}\d+\/\d+\/\d\d\d\d \d{1,2}:\d{1,2}:\d{1,2})\s+\S+\s+PACKET\s+\S+\s+({protocol}\S+)\s+({activity}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+\S+\s+R\s+Q\s+\[\S+\s+(\s|({response_flags}.+?))\s+({dns_response_code}\S+)\]\s+({query_type}\S+)\s+({query}.+?)\s"""
  ]
}
```