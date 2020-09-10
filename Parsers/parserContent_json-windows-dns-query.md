#### Parser Content
```Java
{
Name = json-windows-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """@timestamp":""", """"log_type":"win_dns"""" ]
  Fields = [
    """hostname":"({host}[^"]+)""",
    """message":"({time}\d+\/\d+\/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM)) ({thread_id}\S+)\s+(\S+\s+){2}({protocol}\S+)\s+({activity}\S+)\s+(::1|({src_ip}\S+))\s+({query_id}\S+)\s+\S+ \[\S+\s+(|({query_flags}.+?))\s+({dns_response_code}\S+)\]\s+({query_type}\S+)\s+({query}[^\s"\n]+?)(\\n)?""""
  ]
  DupFields = ["src_ip->src_host"]
}
```