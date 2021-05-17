#### Parser Content
```Java
{
Name = syslog-f5-dns-query-1
  Vendor = F5
  Product = BIG-IP DNS
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """,F5 DNS """, """,question_name=""", """,question_type=""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """,src_ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """,dns_server_ip=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """,question_name=({query}[^,]{1,2000})""",
    """,question_name=({query_1}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})({query_2}[^,]{0,2000})""",
    """,question_type=({query_type}[^,"]{1,2000})""",
  ]
}
```