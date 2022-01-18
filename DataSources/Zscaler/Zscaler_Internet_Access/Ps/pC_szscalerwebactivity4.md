#### Parser Content
```Java
{
Name = s-zscaler-web-activity-4
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Syslog
  DataType = "web-activity"
  Conditions = [ """dlpeng="None"""", """recordid="""", """saction="""", """url="""" ]
  TimeFormat = "MMM  dd HH:mm:ss yyyy z"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """time="\w+\s{0,100}({time}\w+  \d{1,100} \d\d:\d\d:\d\d \d\d\d\d \w+)""",
    """urlcat="({category}[^"]{1,2000})""",
    """respsize="({bytes_in}\d{1,100})""",
    """reqsize="({bytes_out}\d{1,100})""",
    """saction="({action}[^"]{1,2000})""",
    """appname="({app}[^"]{1,2000})""",
    """c-ip="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """url="({full_url}(({protocol}[^:\\\/\s,]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,]{1,2000}))(:\d{1,100})?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s,]{0,2000})?)"""",
    """dhostname="(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^"]{1,2000}))"""",
    """r-ip="({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """csmethod="(NA|({method}[^"]{1,2000}))""",
    """sc-status="(NA|({result_code}\d{1,100}))""",
    """cs\(User-Agent\)="(Unknown|({user_agent}[^"]{1,2000}))""",
    """cs\(Referer\)="(Unknown|None|({referrer}[^"]{1,2000}))""",
    """proto="({protocol}[^"]{1,2000})""",
    """url="({full_url}[^"]{1,2000})""",
    """reason="(Allowed|({failure_reason}[^"]{1,2000}))""",
    """cs\(User-Agent\)="[^=]{0,2000}?({browser}(?:C|c)hrome|(?:S|s)afari|(?:O|o)pera|(?:F|f)irefox|MSIE|(?:T|t)rident)""",
    """cs\(User-Agent\)="[^=]{0,2000}?({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]


}
```