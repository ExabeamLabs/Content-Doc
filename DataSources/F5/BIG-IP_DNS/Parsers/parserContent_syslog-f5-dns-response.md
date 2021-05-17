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
    """({time}\d\d\d\d-\d\d-\d\d (\d\d| \d):\d\d:\d\d)\s{1,100}({src_host}[\w\.-]{1,2000})\s{1,100}qid""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}qid""",
    """\s({src_ip}[\da-fA-F:]{1,2000})\s{1,100}qid""",
    """qid\s{1,100}({query_id}\d{1,100})\s{1,100}to\s{1,100}({dest_ip}[\da-fA-F\.:]{1,2000})(#({dest_port}\d{1,100}))?:""",
    """\[({dns_response_code}\S+)\s{1,100}({response_flags}.+?)\]\s{1,100}response:""",
    """response:\s{0,100}({query}\S+?)\.?\s{1,100}({response_ttl}\d{1,100})\s{1,100}IN\s{1,100}({query_type}\S+)\s{1,100}({response}\S+);""",
    """response:\s{1,100}([^.\s]{1,2000}\.)*({top_query}[^.\s]{1,2000}\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)""",
    """response:\s{0,100}({full_response}.+?)\s{0,100}$"""
  ]
  DupFields = ["src_ip->host", "src_host->host"]
}
```