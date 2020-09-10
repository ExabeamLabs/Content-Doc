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
    """({time}\d\d\d\d-\d\d-\d\d (\d\d| \d):\d\d:\d\d)\s+({host}[\w\.-]+)\s+qid""",
    """qid\s+({query_id}\d+)\s+from\s+({src_ip}[\da-fA-F\.:]+)(#({src_port}\d+))?:""",
    """:\s*view\s+({view}.+?)\s*:""",
    """query:\s*({query}\S+?)\s+IN\s+({query_type}\S+)\s+({query_flags}\S+)\s+(\(({dest_ip}.+?)(%\d+?)\))?""",
    """query:\s*([^.\s]+\.)*({top_query}[^.\s]+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)"""
  ]
  DupFields = ["src_ip->src_host"]
}
```