#### Parser Content
```Java
{
Name = n-cef-bluecoat-proxy
  Vendor = Symantec
  Product = Blue Coat ProxySG Appliance
  Lms = NitroCefSyslog
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """nitroQuery_Response=""" ]
  Fields = [
    """\|McAfee\|ESM\|([^|]+?\|){2}({method}\w+)\s+({proxy_action}\w+)\s+({action}\w+)\|""",
    """\|McAfee\|ESM\|([^|]+?\|){2}({alert_name}[^|]+)\|""",
    """\Wrt=({time}\d+)""",
    """\WdeviceDirection=({direction}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({web_domain}.*?)\s+(\w+=|$)""",
    """\Wsuser=({user}.*?)\s+(\w+=|$)""",
    """\WnitroResponse_Code=({result_code}\d+)""",
    """\WnitroCategory=({category}.*?)\s+(\w+=|$)""",
    """\WnitroQuery_Response=({action}.*?)\s+(\w+=|$)""",
    """\WnitroURL=({uri_path}[^=\?]*?)(\?({uri_query}.*?))?\s+(\w+=|$)""",
    """\Wsntdom=.*?({top_domain}[^.]+(\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s+(\w+=|$)""",
    """\Wduser=({user_agent}.+?)\s+(\w+=|$)""",
    """\Wduser=[^=]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\Wduser=[^=]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```