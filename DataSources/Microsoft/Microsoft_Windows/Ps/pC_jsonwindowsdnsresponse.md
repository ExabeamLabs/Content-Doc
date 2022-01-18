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
    """hostname":"({host}[^"]{1,2000})""",
    """message":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM)) ({thread_id}\S+)\s{1,100}(\S+\s{1,100}){2}({protocol}\S+)\s{1,100}({activity}\S+)\s{1,100}(::1|({dest_ip}\S+))\s{1,100}({query_id}\S+)\s{1,100}R \S+ \[\S+\s{1,100}(|({query_flags}.+?))\s{1,100}({dns_response_code}\S+)\]\s{1,100}({query_type}\S+)\s{1,100}({query}[^\s"\n]{1,2000}?)(\\n)?""""
  ]


}
```