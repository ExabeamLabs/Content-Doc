#### Parser Content
```Java
{
Name = json-windows-dns-response
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """@timestamp":""", """"log_type":"win_dns"""", """ R """ ]
  Fields = [
    """hostname":"({host}[^"]+)""",
    """message":"({time}\d+\/\d+\/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM)) ({thread_id}\S+)\s+(\S+\s+){2}({protocol}\S+)\s+({activity}\S+)\s+(::1|({dest_ip}\S+))\s+({query_id}\S+)\s+R \S+ \[\S+\s+(|({query_flags}.+?))\s+({dns_response_code}\S+)\]\s+({query_type}\S+)\s+({query}[^\s"\n]+?)(\\n)?""""
  ]
}
```