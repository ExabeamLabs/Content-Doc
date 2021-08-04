#### Parser Content
```Java
{
Name = cef-bluecoat-proxy
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Blue Coat|Proxy SG|""", """requestMethod=""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}.+?)\s\w+=""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdst=({dest_ip}.+?)\s\w+=""",
    """\ssrc=({src_ip}.+?)\s\w+=""",
    """\sshost=({src_host}.+?)\s\w+=""",
    """\sdpt=({dest_port}\d{1,100})\s\w+=""",
    """\ssuser=({user}.+?)\s\w+=""",
    """\sact=({action}.+?)\s\w+=""",
    """\srequestMethod=({method}.+?)\s\w+=""",
    """\sout=({bytes_out}\d{1,100})\s\w+=""",
    """\sin=({bytes_in}.+?)\s\w+=""",
    """\srequestProtocol=(?:-|({protocol}.+?))\s\w+=""",
    """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
    """\srequest=(?:(-|)|({full_url}.+?))\s\w+=""",
    """\srequestUrlFileName=(?:(-|)|({uri_path}.+?))\s\w+=""",
    """\srequestUrlQuery=(?:-|({uri_query}.+?))\s\w+=""",
    """\srequestClientApplication=(?:-|({user_agent}.+?))\s\w+=""",
    """\scat=(?:(none)|({category}.+?)(;.+?)?)\s{1,100}\w+=""",
    """\s(cs1|fileType)=(?:-|({mime}.+?)(;.+?)?)\s\w+=""",
    """\scn1=(?:-|({result_code}.+?)(;.+?)?)\s\w+=""",
    """\|Blue Coat\|Proxy SG\|[^|]{0,2000}\|({proxy_action}[^|]{1,2000})\|""",
    """\sdhost=([^=]{0,2000}?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+\s\w+=)[^\s]{1,2000})"""
    """requestClientApplication=(?:-|({browser}[\w\-]{1,2000}))""",
    """requestClientApplication=(?:-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
    """requestClientApplication=(?:-|({browser}[^=\/]{1,2000})\/[^=]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))[^=]{0,2000}\s\w+=""",
    """requestClientApplication=(?:-|Mozilla\/[^=]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))[^=]{0,2000}\s\w+=""",
    """requestClientApplication=(?:-|Mozilla\/[^=]{1,2000}\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}Gecko\/\d{1,100}\s{1,100}({browser}\w+))[^=]{0,2000}\s\w+=""",
    """requestContext=(?:-|({referrer}[^\s]{1,2000}))""",
  ]
  DupFields = [ "user->orig_user" ]
}
```