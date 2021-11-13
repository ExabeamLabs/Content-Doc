#### Parser Content
```Java
{
Name = syslog-f5-dns-query
  Vendor = F5
  Product = BIG-IP DNS
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " qid ", " from ", " query:", " IN " ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d (\d\d| \d):\d\d:\d\d)\s{1,100}({host}[\w\.-]{1,2000})\s{1,100}qid""",
    """qid\s{1,100}({query_id}\d{1,100})\s{1,100}from\s{1,100}({src_ip}[\da-fA-F\.:]{1,2000})(#({src_port}\d{1,100}))?:""",
    """:\s{0,100}view\s{1,100}({view}.+?)\s{0,100}:""",
    """query:\s{0,100}({query}\S+?)\s{1,100}IN\s{1,100}({query_type}\S+)\s{1,100}({query_flags}\S+)\s{1,100}(\(({dest_ip}.+?)(%\d{1,100}?)\))?""",
  ]


}
```