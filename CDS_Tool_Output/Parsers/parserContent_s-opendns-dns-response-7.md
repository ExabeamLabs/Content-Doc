#### Parser Content
```Java
{
Name = s-opendns-dns-response-7
  Conditions = [ ""","Allowed","2 (NS)",""" ]
}

${CiscoParsersTemplates.s-opendns-dns-response} {
  Name = s-opendns-dns-response-8
  Conditions = [ ""","Allowed","5 (CNAME)",""" ]
}

${CiscoParsersTemplates.s-opendns-dns-response} {
  Name = s-opendns-dns-response-9
  Conditions = [ ""","Allowed","15 (MX)",""" ]
}

${CiscoParsersTemplates.s-opendns-dns-response} {
  Name = s-opendns-dns-response-10
  Conditions = [ ""","Allowed","35 (NAPTR)",""" ]
}

  {
    Name = sourcefire-proxy
    Vendor = Cisco
    Product = Cisco Firepower
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """SFIMS""", """Policy: Default Access Control""", """ApplicationProtocol: HTTP""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """SrcIP:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """DstIP:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """SrcPort:\s*({src_port}\d+)""",
      """DstPort:\s*({dest_port}\d+)""",
      """AccessControlRuleAction:\s*({action}[^,]+)""",
      """UserName:\s*({user}[^,]+)""",
      """Client:\s*({user_agent}[^,]+)""",
      """UserAgent:\s*({user_agent}.+?),\s*Client:""",
      """UserAgent:\s*({browser}\w\-.)""",
      """UserAgent:(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """UserAgent:(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """UserAgent:(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
      """Client:\s*({browser}[^,]+)""",
      """ApplicationProtocol:\s*({protocol}[^,]+)""",
      """InitiatorBytes:\s*({bytes_out}[^,]+)""",
      """ResponderBytes:\s*({bytes_in}[^,]+)""",
      """URLCategory:\s*({category}[^,]+)""",
      """URL:\s*({full_url}\S+?)(,\s*\w+:|\s)""",
      """URL:\s*(?:-|\w+:\/+)({web_domain}[^\s\/]+)""",
      """URL:\s*(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
      """URL:\s*.*?({uri_query}\?[^\s"]+)""",
      """URL:(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(,|\/|\s))[^,\/\s]+)"""
    ]
  }
```