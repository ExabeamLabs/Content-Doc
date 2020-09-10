#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-alert
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Conditions = [ "|Forcepoint|TRITON AP-DATA", "sourceServiceName=" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}[\d.]+)""",
    """\sdvchost=({host}[^\s]*)""",
    """\ssuser=({user_fullname}.+?)(\s+\(.+\))?\s\w+=""",
    """loginName=(({domain}[^\\]+)\\+)?({user}[^,=]+)\s+([\w\.]+=|$)""",
    """sourceIp=(?:N\/A|({src_ip}.+?))\s+([\w\.]+=|$)""",
    """sourceHost=({src_host}.+?)\s+([\w\.]+=|$)""",
    """\sduser=[^\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s+\w+=""",
    """\sfname=(N\/A|.*?[\/\\]*({file_name}[^\\\/]+))\s+\- [\d.]+ """,
    """\sfname=(N\/A|.*? - ({bytes_num}[\d.]+)\s+({bytes_unit}[^\s;]+))""",
    """\ssourceServiceName=({alert_type}.+?)\s+(on |\w+=)""",
    """\scat=\**({alert_name}.+?)(\*|\s\-\s|\s+[\w\.]+=)""",
    """\|Forcepoint\|(.+?\|){4}({alert_severity}[^|]+)""",
    """\sact=({outcome}[^\s]*)"""
  ]
}
```