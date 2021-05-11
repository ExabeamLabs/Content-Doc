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
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w.-]+)""",
    """\tcs-userdn=(?:-|(({domain}[^\\\t]+)\\)?({user}[^\s\t]+))""",
    """\Ws-ip="?(-|({host}[^"|]+))("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Ws-computername="?(-|({host}[^"|]))("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """date="?({time}\d\d\d\d-\d\d-\d\d"?(,|\t|\s)time="?\d\d:\d\d:\d\d)""",
    """\Wdevicetime=\[({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\s{0,100}\d{1,100}:\d{1,100}:\d{1,100} [^\]]+)""",
    """date="({time}\d\d\/\d\d\/\d\d\d\d:\s\d\d:\d\d:\d\d[^"]+)"""",
    """\W(c-ip|src)="?(-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\tr-ip=(-|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wsrcport=(-|({src_port}\d{1,100}))""",
    """\Wdst=(-|({external_dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wdstport=(?:-|({dest_port}\d{1,100}))""",
    """\W(cs-username|username)="?(-|({user}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Ws-action="?(-|({proxy_action}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\W(sc|cs)-status="?(-|({result_code}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-method="?((?i)(unknown)|-|({method}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\W(sc|rs)-bytes="?(-|({bytes_out}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-bytes="?(-|({bytes_in}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-uri-scheme="?(-|({protocol}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-host="?(-|({web_domain}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-uri="?(-|({full_url}[^"|]+))\s{0,100}(?:"|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-uri-path="?(\/|-|({uri_path}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-uri-query="?(-|({uri_query}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-uri-extension="?(-|({mime}[^"|]+))\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]+=)""",
    """\Wrs\(\s?Content\-Type\)="?(-|({mime}[^"|]+))\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs\(User-Agent\)="?(-|({user_agent}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\W(sc-)?filter-result="?(-|({action}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\W(sc-)?filter-category="?((?i)none|-|({category}[^"|]+))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-categories="?((?i)none|-|({category}[^"|]+))"?\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs-categories="?((?i)none|-|({categories}[^"|]+))"?\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs\(User-Agent\)="?(-|({browser}[\w\-]+))""",
    """\Wcs\(User-Agent\)="?(-|({browser}[\w\-]+)\/[\d\._]+)""",
    """\Wcs\(User-Agent\)="?(-|({browser}[^\/]+)[^=]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\Wcs\(User-Agent\)="?(-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wcs\(User-Agent\)="?(-|Mozilla\/[^=]+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
    """\Wcs-usr-agent="?(-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wcs-host="?([^"=]+?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\t]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)""",
    """\Wcs\(Referer\)"?=("?-"?|"?({referrer}[^"\|\t]+?)"?)\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]+=)"""
  ]
}
```