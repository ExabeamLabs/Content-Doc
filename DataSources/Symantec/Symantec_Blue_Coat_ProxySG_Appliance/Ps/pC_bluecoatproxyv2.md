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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.-]{1,2000})""",
    """\tcs-userdn=(?:-|(({domain}[^\\\t]{1,2000})\\)?({user}[^\s\t]{1,2000}))""",
    """\Ws-ip="?(-|({host}[^"|]{1,2000}))("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Ws-computername="?(-|({host}[^"|]))("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """date="?({time}\d\d\d\d-\d\d-\d\d"?(,|\t|\s)time="?\d\d:\d\d:\d\d)""",
    """\Wdevicetime=\[({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\s{0,100}\d{1,100}:\d{1,100}:\d{1,100} [^\]]{1,2000})""",
    """date="({time}\d\d\/\d\d\/\d\d\d\d:\s\d\d:\d\d:\d\d[^"]{1,2000})"""",
    """\W(c-ip|src)="?(-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\tr-ip=(-|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wsrcport=(-|({src_port}\d{1,100}))""",
    """\Wdst=(-|({external_dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wdstport=(?:-|({dest_port}\d{1,100}))""",
    """\W(cs-username|username)="?(-|({user}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Ws-action="?(-|({proxy_action}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc|cs)-status="?(-|({result_code}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-method="?((?i)(unknown)|-|({method}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc|rs)-bytes="?(-|({bytes_out}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-bytes="?(-|({bytes_in}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-scheme="?(-|({protocol}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-host="?(-|({web_domain}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri="?(-|({full_url}[^"|]{1,2000}))\s{0,100}(?:"|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-path="?(\/|-|({uri_path}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-query="?(-|({uri_query}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-extension="?(-|({mime}[^"|]{1,2000}))\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wrs\(\s?Content\-Type\)="?(-|({mime}[^"|]{1,2000}))\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs\(User-Agent\)="?(-|({user_agent}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc-)?filter-result="?(-|({action}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc-)?filter-category="?((?i)none|-|({category}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-categories="?((?i)none|-|({category}[^"|]{1,2000}))"?\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-categories="?((?i)none|-|({categories}[^"|]{1,2000}))"?\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs\(User-Agent\)="?(-|({browser}[\w\-]{1,2000}))""",
    """\Wcs\(User-Agent\)="?(-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
    """\Wcs\(User-Agent\)="?(-|({browser}[^\/]{1,2000})[^=]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\Wcs\(User-Agent\)="?(-|Mozilla\/[^=]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wcs\(User-Agent\)="?(-|Mozilla\/[^=]{1,2000}\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
    """\Wcs-usr-agent="?(-|Mozilla\/[^=]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wcs-host="?([^"=]{1,2000}?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\t]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs\(Referer\)"?=("?-"?|"?({referrer}[^"\|\t]{1,2000}?)"?)\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)"""
  ]


}
```