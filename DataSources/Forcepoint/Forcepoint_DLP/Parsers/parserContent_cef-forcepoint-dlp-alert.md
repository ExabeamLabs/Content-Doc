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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[\d.]{1,2000})""",
    """\sdvchost=({host}[^\s]{0,2000})""",
    """\ssuser=({user_fullname}.+?)(\s{1,100}\(.+\))?\s\w+=""",
    """loginName=(({domain}[^\\]{1,2000})\\+)?({user}[^,=]{1,2000})\s{1,100}([\w\.]{1,2000}=|$)""",
    """sourceIp=(?:N\/A|({src_ip}.+?))\s{1,100}([\w\.]{1,2000}=|$)""",
    """sourceHost=({src_host}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\sduser=[^\s]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s{1,100}\w+=""",
    """\sfname=(N\/A|.*?[\/\\]{0,2000}({file_name}[^\\\/]{1,2000}))\s{1,100}\- [\d.]{1,2000} """,
    """\sfname=(N\/A|.*? - ({bytes_num}[\d.]{1,2000})\s{1,100}({bytes_unit}[^\s;]{1,2000}))""",
    """\ssourceServiceName=({alert_type}.+?)\s{1,100}(on |\w+=)""",
    """\scat=\**({alert_name}.+?)(\*|\s\-\s|\s{1,100}[\w\.]{1,2000}=)""",
    """\|Forcepoint\|([^|]{1,2000}?\|){4}({alert_severity}[^|]{1,2000})""",
    """\sact=({outcome}[^\s]{0,2000})"""
  ]
}
```