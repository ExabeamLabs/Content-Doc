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
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,[^,]+,[^,]+,({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z),({src_ip}[^,]*?),({dest_ip}[^,]*?),({src_translated_ip}[^,]+),({dest_translated_ip}[^,]+)""",
    """,THREAT,([^,]*?,){8}(({user_email}[^@]+@[^\.]+\.[^,]+)|({user}[^,]+))"""
    """THREAT,url,([^,]*,){21}(?:|({src_port}\d{1,100})),(?:|({dest_port}\d{1,100})),[^,]*,(?:|({protocol}[^,]+)),(?:|({action}[^,]*)),""",
    """THREAT,url,([^,]*,){26}("{1,20})?({full_url}[^\\\/\s:,"]+({uri_path}\/[^\?\s,]+)?)"""
    """Informational,([^,]*,){11}("{1,20})?(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?([uU]nknown|({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)))""",
    """Informational,([^,]*,){11}"{1,20}({user_agent}.+?)\s{0,100}"""",
    """THREAT,url,([^,]*,){26}("{1,20})?.*?({web_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]"""
    """,(any|({category}[^,]+?)),Informational,client to server,"""
  ]
}
```