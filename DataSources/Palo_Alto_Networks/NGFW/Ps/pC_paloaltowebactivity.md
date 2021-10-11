#### Parser Content
```Java
{
Name = paloalto-web-activity
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,url,""", """web-browsing,"""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,[^,]{1,2000},[^,]{1,2000},({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """THREAT,[^,]{1,2000},[^,]{1,2000},({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z),""",
    """THREAT,([^,]{1,2000},){3}({src_ip}[^,]{0,2000}?),({dest_ip}[^,]{0,2000}?),({src_translated_ip}[^,]{1,2000}),({dest_translated_ip}[^,]{1,2000})""",
    """,THREAT,([^,]{0,2000}?,){8}(({user_email}[^@,]{1,2000}@[^\.]{1,2000}\.[^,]{1,2000})|(({domain}[^\\]{1,2000}?)\\)?({user}[^,]{1,2000}))"""
    """THREAT,url,([^,]{0,2000},){21}(?:|({src_port}\d{1,100})),(?:|({dest_port}\d{1,100})),[^,]{0,2000},(?:|({protocol}[^,]{1,2000})),(?:|({action}[^,]{0,2000})),""",
    """THREAT,url,([^,]{0,2000},){26}("{1,20})?({full_url}[^\\\/\s:,"]{1,2000}({uri_path}\/[^\?\s,]{1,2000})?)"""
    """Informational,([^,]{0,2000},){11}("{1,20})?(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?([uU]nknown|({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)))""",
    """Informational,([^,]{0,2000},){11}"{1,20}({user_agent}.+?)\s{0,100}"""",
    """THREAT,url,([^,]{0,2000},){26}("{1,20})?.*?({web_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]"""
    """,(any|({category}[^,]{1,2000}?)),Informational,client to server,"""
  ]
}
```