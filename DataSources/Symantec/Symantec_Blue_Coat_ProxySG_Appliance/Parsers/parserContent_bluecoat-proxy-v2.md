#### Parser Content
```Java
{
Name = bluecoat-proxy-v2
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MM/yyyy:HH:mm:ss z"
  Conditions = [ """filter-result=""", """cs-host=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w.-]+)""",
    """\tcs-userdn=(?:-|(({domain}[^\\\t]+)\\)?({user}[^\s\t]+))""",
    """\Ws-ip="?(-|({host}[^"|]+))("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Ws-computername="?(-|({host}[^"|]))("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """date="?({time}\d\d\d\d-\d\d-\d\d"?(,|\t|\s)time="?\d\d:\d\d:\d\d)""",
    """\Wdevicetime=\[({time}\d+\/\d+\/\d+:\s*\d+:\d+:\d+ [^\]]+)""",
    """date="({time}\d\d\/\d\d\/\d\d\d\d:\s\d\d:\d\d:\d\d[^"]+)"""",
    """\W(c-ip|src)="?(-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\tr-ip=(-|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wsrcport=(-|({src_port}\d+))""",
    """\Wdst=(-|({external_dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wdstport=(?:-|({dest_port}\d+))""",
    """\W(cs-username|username)="?(-|({user}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Ws-action="?(-|({proxy_action}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\W(sc|cs)-status="?(-|({result_code}\d+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-method="?((?i)(unknown)|-|({method}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\W(sc|rs)-bytes="?(-|({bytes_out}\d+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-bytes="?(-|({bytes_in}\d+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-uri-scheme="?(-|({protocol}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-host="?(-|({web_domain}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-uri="?(-|({full_url}[^"|]+))\s*(?:"|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-uri-path="?(\/|-|({uri_path}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-uri-query="?(-|({uri_query}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-uri-extension="?(-|({mime}[^"|]+))\s*("|\||$|\t|;|\s+[\w\-\(\)]+=)""",
    """\Wrs\(\s?Content\-Type\)="?(-|({mime}[^"|]+))\s*("|\||$|\t|;|\s+[\w\-\(\)]+=)""",
    """\Wcs\(User-Agent\)="?(-|({user_agent}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\W(sc-)?filter-result="?(-|({action}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\W(sc-)?filter-category="?((?i)none|-|({category}[^"|]+))\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs-categories="?((?i)none|-|({category}[^"|]+))"?\s*("|\||$|\t|;|\s+[\w\-\(\)]+=)""",
    """\Wcs-categories="?((?i)none|-|({categories}[^"|]+))"?\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs\(User-Agent\)="?(-|({browser}[\w\-]+))""",
    """\Wcs\(User-Agent\)="?(-|({browser}[\w\-]+)\/[\d\._]+)""",
    """\Wcs\(User-Agent\)="?(-|({browser}[^\/]+)[^=]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\Wcs\(User-Agent\)="?(-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wcs\(User-Agent\)="?(-|Mozilla\/[^=]+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+Gecko\/\d+\s+({browser}\w+))""",
    """\Wcs-usr-agent="?(-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wcs-host="?([^"=]+?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\t]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s*("|\||$|\t|\s+[\w\-\(\)]+=)""",
    """\Wcs\(Referer\)"?=("?-"?|"?({referrer}[^"\|\t]+?)"?)\s*("|\||$|\t|\s+[\w\-\(\)]+=)"""
  ]
}
```