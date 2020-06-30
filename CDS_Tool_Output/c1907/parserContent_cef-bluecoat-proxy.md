#### Parser Content
```Java
{
Name = cef-bluecoat-proxy
  Vendor = Symantec
  Product = Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Blue Coat|Proxy SG|""", """requestMethod=""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}.+?)\s\w+=""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdst=({dest_ip}.+?)\s\w+=""",
    """\ssrc=({src_ip}.+?)\s\w+=""",
    """\sshost=({src_host}.+?)\s\w+=""",
    """\sdpt=({dest_port}\d+)\s\w+=""",
    """\ssuser=({user}.+?)\s\w+=""",
    """\sact=({action}.+?)\s\w+=""",
    """\srequestMethod=({method}.+?)\s\w+=""",
    """\sout=({bytes_out}\d+)\s\w+=""",
    """\sin=({bytes_in}.+?)\s\w+=""",
    """\srequestProtocol=(?:-|({protocol}.+?))\s\w+=""",
    """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
    """\srequest=(?:(-|)|({full_url}.+?))\s\w+=""",
    """\srequestUrlFileName=(?:(-|)|({uri_path}.+?))\s\w+=""",
    """\srequestUrlQuery=(?:-|({uri_query}.+?))\s\w+=""",
    """\srequestClientApplication=(?:-|({user_agent}.+?))\s\w+=""",
    """\scat=(?:(none)|({category}.+?)(;.+?)?)\s+\w+=""",
    """\s(cs1|fileType)=(?:-|({mime}.+?)(;.+?)?)\s\w+=""",
    """\scn1=(?:-|({result_code}.+?)(;.+?)?)\s\w+=""",
    """\|Blue Coat\|Proxy SG\|[^|]*\|({proxy_action}[^|]+)\|""",
    """\sdhost=([^=]*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+\s\w+=)[^\s]+)"""
    """requestClientApplication=(?:-|({browser}[\w\-]+))""",
    """requestClientApplication=(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
    """requestClientApplication=(?:-|({browser}[^=\/]+)\/[^=]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))[^=]*\s\w+=""",
    """requestClientApplication=(?:-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))[^=]*\s\w+=""",
    """requestClientApplication=(?:-|Mozilla\/[^=]+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+Gecko\/\d+\s+({browser}\w+))[^=]*\s\w+=""",
    """requestContext=(?:-|({referrer}[^\s]+))""",
  ]
  DupFields = [ "user->orig_user" ]
}
```