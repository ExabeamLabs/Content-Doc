#### Parser Content
```Java
{
Name = syslog-f5-dns-response
  Vendor = F5
  Product = BIG-IP DNS
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " qid ", " to ", " response:" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d (\d\d| \d):\d\d:\d\d)\s+({src_host}[\w\.-]+)\s+qid""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+qid""",
    """\s({src_ip}[\da-fA-F:]+)\s+qid""",
    """qid\s+({query_id}\d+)\s+to\s+({dest_ip}[\da-fA-F\.:]+)(#({dest_port}\d+))?:""",
    """\[({dns_response_code}\S+)\s+({response_flags}.+?)\]\s+response:""",
    """response:\s*({query}\S+?)\.?\s+({response_ttl}\d+)\s+IN\s+({query_type}\S+)\s+({response}\S+);""",
    """response:\s+([^.\s]+\.)*({top_query}[^.\s]+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)""",
    """response:\s*({full_response}.+?)\s*$"""
  ]
  DupFields = ["src_ip->host", "src_host->host"]
}
```