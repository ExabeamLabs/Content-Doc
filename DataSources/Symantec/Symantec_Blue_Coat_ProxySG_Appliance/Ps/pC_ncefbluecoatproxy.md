#### Parser Content
```Java
{
Name = n-cef-bluecoat-proxy
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = NitroCefSyslog
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """nitroQuery_Response=""" ]
  Fields = [
    """\|McAfee\|ESM\|([^|]{1,2000}?\|){2}({method}\w+)\s{1,100}({proxy_action}\w+)\s{1,100}({action}\w+)\|""",
    """\|McAfee\|ESM\|([^|]{1,2000}?\|){2}({alert_name}[^|]{1,2000})\|""",
    """\Wrt=({time}\d{1,100})""",
    """\WdeviceDirection=({direction}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsntdom=({web_domain}.*?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}.*?)\s{1,100}(\w+=|$)""",
    """\WnitroResponse_Code=({result_code}\d{1,100})""",
    """\WnitroCategory=({category}.*?)\s{1,100}(\w+=|$)""",
    """\WnitroQuery_Response=({action}.*?)\s{1,100}(\w+=|$)""",
    """\WnitroURL=({uri_path}[^=\?]{0,2000}?)(\?({uri_query}.*?))?\s{1,100}(\w+=|$)""",
    """\Wsntdom=.*?({top_domain}[^.]{1,2000}(\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_agent}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=[^=]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\Wduser=[^=]{0,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]


}
```