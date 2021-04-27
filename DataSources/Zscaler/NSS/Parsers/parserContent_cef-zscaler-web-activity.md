#### Parser Content
```Java
{
Name = cef-zscaler-web-activity
  Vendor = Zscaler
  Product = NSS
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Zscaler|NSSWeblog|""", """requestClientApplication=""", """act=""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\srt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+) CEF:""",
    """\sdvchost=({host}[\w\-.]+)\s*(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """\sdst=({dest_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """([^\|]*\|){5}({action}[^\|]+)""",
    """(\s|\|)act=({action}.+?)\s*(\w+=|$)""",
    """\ssuser=(NA|None|\$NULL|(?![^\s]+@[^\s]+)({user}.+?))\s*(\w+=|$)""",
    """\ssuser=({user_email}({user}[^\s@]+)@[^\s]+)\s*(\w+=|$)""",
    """\sapp=({protocol}.+?)\s*(\w+=|$)""",
    """\srequestProtocol=({protocol}.+?)\s*(\w+=|$)""",
    """\scs4=(None|({ransomware_name}.+?)\s*(\w+=|$))""",
    """\srequest=({full_url}.+?)\s*(\w+=|$)""",
    """\srequest=(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s]+)(\?\S+)?\s+(\w+=|$)""",
    """\srequest=(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?[^\s]+)""",
    """\srequest=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)""",
    """\srequest=[^\s?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s\w+=|\/))[^\s:\/]+)""",
    """\srequestMethod=(NA|({method}.+?))\s*(\w+=|$)""",
    """\srequestClientApplication=([uU]nknown|({user_agent}.+?))\s*(\w+=|$)""",
    """\srequestClientApplication=([uU]nknown|({browser}.+?))\s*(\w+=|$)""",
    """\scn1=({risk_level}.+?)\s*(\w+=|$)""",
    """\sout=({bytes_in}\d+)""",
    """\sin=({bytes_out}\d+)""",
    """\s(ad\.)?ZscalerNSSWeblogURLClass=({category}.+?)\s*(\w+=|$)""",
    """\sfileType=(None|({mime}.+?))\s*(\w+=|$)""",
    """\soutcome=({result_code}\d+)""",
    """\sreason=({proxy_action}.+?)\s*(\w+=|$)""",
    """\srequestClientApplication=(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?([uU]nknown|({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)))""",
    """\scs1=({department}.+?)\s*(\w+=|$)""",
    """\scs2=({categories}.+?)\s*(\w+=|$)""",
    """\scs5=(None|({threat_name}.+?))\s*(\w+=|$)""",
    """\scs6=(None|({dlp_engine}.+?))\s*(\w+=|$)""",
    """sourcehost=(NA|None|\$NULL|({src_host}.+?))\s+destinationhost=""",
    """destinationhost=(NA|None|\$NULL|({dest_host}.+?))\s+\w+""",
    """devicehostname=({src_host}[^\s"]+?)\s*(\w+=|$)""",
    """ZscalerNSSWeblogDLPDictionaries=(None|({web_log_dict}[^=]+?))\s*([\w.]+=|$)"""
  ]
  DupFields = ["ransomware_name->threat_category", "risk_level->suspicious_content"]
}
```