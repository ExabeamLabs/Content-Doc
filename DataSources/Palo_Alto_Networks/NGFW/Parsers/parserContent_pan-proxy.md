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
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s+\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]*,THREAT,url,""",
    """THREAT,url,\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({src_ip}[a-fA-F\d.:]+),({dest_ip}[a-fA-F\d.:]+),""",
    """THREAT,url,([^,]*,){5,8}(({domain}[^\\,]+)\\)(?:|({user}[^,]+)),""",
    """THREAT,url,([^,]*,){21}(?:|({src_port}\d+)),(?:|({dest_port}\d+)),[^,]*,(?:|({protocol}[^,]+)),(?:|({action}[^,]*)),""",
    """THREAT,url,.+?\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d,(\d+,){2}(?:|({src_port}\d+)),(?:|({dest_port}\d+)),(?:|({protocol}[^,]+)),(?:|({action}[^,]+)),"""",
    """THREAT,url,.+?"+(?:\\|({full_url}({web_domain}[^\\\/\s:,"]+)(:({dest_port}\d+))?({uri_path}\/[^\?\s]*?)?(\/|({uri_query}\?[^\s]*?))?))"*,\(9999\),(?:|unknown|({category}[^,]+)),""",
    """\(9999\),([^,]*,){8}"?({mime}[^,"]+)""",
    """\(9999\),([^,]*,){8}((".+?")|([^,]*)),([^,]*,){4}({user_agent}[^,]+),""",
    """\(9999\),([^,]*,){8}((".+?")|([^,]*)),([^,]*,){4}"({user_agent}[^"]+)",""",
    """\(9999\),([^,]*,){8}((".+?")|([^,]*)),([^,]*,){4}"?[^",]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\(9999\),([^,]*,){8}((".+?")|([^,]*)),([^,]*,){4}"[^"]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\(9999\),([^,]*,){8}((".+?")|([^,]*)),([^,]*,){4}[^",]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """THREAT,url,.+?,"*[^"]*?({top_domain}(?!(?:\d+\.){3}\d+)[^,"\.\s:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|digital|cool|network|im|as|ke|fm|mx|br|citrix|live))+(\"|\/|:))[^\/]+).*?",\(9999\),""",
    """"*({referrer}[^,"\s]+)"*,([^,]*,){10}\s+$""",
  ]
}
```