#### Parser Content
```Java
{
Name = cef-zscaler-web-activity
  Vendor = Zscaler
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
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
    """\ssuser=(?![^\s]+@[^\s]+)({user}.+?)\s*(\w+=|$)""",
    """\ssuser=({user_email}({user}[^\s@]+)@[^\s]+)\s*(\w+=|$)""",
    """\sapp=({protocol}.+?)\s*(\w+=|$)""",
    """\srequestProtocol=({protocol}.+?)\s*(\w+=|$)""",
    """\scs4=({ransomware_name}.+?)\s*(\w+=|$)""",
    """\srequest=({full_url}.+?)\s*(\w+=|$)""",
    """\srequest=(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s]+)(\?\S+)?\s+(\w+=|$)""",
    """\srequest=(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?[^\s]+)""",
    """\srequest=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)""",
    """\srequest=[^\s?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s\w+=|\/))[^\s:\/]+)""",
    """\srequestMethod=({method}.+?)\s*(\w+=|$)""",
    """\srequestClientApplication=({user_agent}.+?)\s*(\w+=|$)""",
    """\srequestClientApplication=({browser}.+?)\s*(\w+=|$)""",
    """\scn1=({risk_level}.+?)\s*(\w+=|$)""",
    """\sout=({bytes_in}\d+)""",
    """\sin=({bytes_out}\d+)""",
    """\s(ad\.)?ZscalerNSSWeblogURLClass=({category}.+?)\s*(\w+=|$)""",
    """\sfileType=({mime}.+?)\s*(\w+=|$)""",
    """\soutcome=({result_code}\d+)""",
    """\sreason=({proxy_action}.+?)\s*(\w+=|$)""",
    """\srequestClientApplication=(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
}
```