#### Parser Content
```Java
{
Name = pan-proxy
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,url,""", """(9999)"""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({host}[\w\-\.]{1,2000})[\s\-]{1,2000}\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]{0,2000},THREAT,url,""",
    """THREAT,("[^"]{0,2000}",|[^,]{0,2000},){55}({host}[\w\-\.]{1,2000})""",
    """:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s""",
    """THREAT,url,\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({src_ip}[a-fA-F\d.:]{1,2000}),({dest_ip}[a-fA-F\d.:]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){5,8}(({domain}[^\\,]{1,2000})\\)(|({user}[^,]{1,2000})),""",
    """THREAT,url,([^,]{0,2000},){4}((\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3},)))?[^,]{1,2000},(|(({domain}[^\\,]{1,2000})\\)?({user}[^,]{1,2000})),""",
    """THREAT,url,([^,]{0,2000},){19}(|({src_port}\d{1,100})),(|({dest_port}\d{1,100})),([^,]{0,2000},){3}(|({protocol}[^,]{1,2000})),(|({action}[^,]{0,2000})),""",
    """THREAT,url,.+?"{1,20}(?:\\|({full_url}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))(:({dest_port}\d{1,100}))?({uri_path}\/[^\?\s]{0,2000}?)?(\/|({uri_query}\?[^\s]{0,2000}?))?))"{0,20},\(9999\),""",
    """\(9999\),([^,]{0,2000},){8}"?({mime}[^,"]{1,2000})""",
    """\(9999\),([^,]{0,2000},){8}((".+?")|([^,]{0,2000})),([^,]{0,2000},){4}"{0,100}({user_agent}[^,]{1,2000}),""",
    """\(9999\),([^,]{0,2000},){8}((".+?")|([^,]{0,2000})),([^,]{0,2000},){4}"{1,100}({user_agent}[^"]{1,2000}?)\s{0,100}",""",
    """\(9999\),([^,]{0,2000},){8}((".+?")|([^,]{0,2000})),([^,]{0,2000},){4}"?[^",]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\(9999\),([^,]{0,2000},){8}((".+?")|([^,]{0,2000})),([^,]{0,2000},){4}.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^,]{1,2000},""",
    """THREAT,url,([^,]{0,2000},){26}"[^"]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^,"\.\s:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|digital|cool|network|im|as|ke|fm|mx|br|citrix|live|ms))+(\"|\/|:))[^\/]{1,2000}).*?",\(9999\),""",
    """\(9999\),([^,]{0,2000},){16}(|"?({referrer}[^,"\s]{1,2000}?)"?)\s{0,100},([^,]{0,2000},){13}(|({method}[^,"\s]{1,2000}?))\s{0,100},""",
    """,(?i)({method}connect|get|head|post),"""
    """THREAT,url,([^,]{0,2000},){26}("{1,20})?[^\s"]{0,2000}?({web_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]""",
    """\(9999\),(("[^"]{1,2000}?"|[^,]{0,2000}),){36}(N/A|unknown|({threat_category}[^,]{1,2000})),""",
    """\(9999\),({category}[^,]{1,2000}),"""
    """THREAT,url,([^,]{0,2000},){6}({rule}[^,]{1,2000})""",
    """THREAT,url,([^,]{0,2000},){9}({network_app}[^,]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){11}({src_network_zone}[^,]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){12}({dest_network_zone}[^,]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){13}({src_interface}[^,]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){14}({dest_interface}[^,]{1,2000}),""",
    """\(9999\),[^,]{0,2000},({severity}[^,]{1,2000}),"""
  ]
}
```