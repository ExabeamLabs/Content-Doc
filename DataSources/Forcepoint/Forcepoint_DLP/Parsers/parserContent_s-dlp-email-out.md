#### Parser Content
```Java
{
Name = s-dlp-email-out
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "CEF:","|Websense|Data Security", "sourceServiceName=" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\sloginName=(({domain}[^\\]+)\\+)?({user}.+?)\s+(\w+=|$)""",
    """sourceServiceName=(SMTP|Endpoint Email).+?suser=([^\\]+\\+)?({sender}.+?)\s+(\w+=|$)""",
    """sourceServiceName=(SMTP|Endpoint Email).+?loginName=([^\\]+\\+)?({sender}.+?)\s+(\w+=|$)""",
    """\sduser=\\*(({target_domain}[^\\]+)\\+)?({target}.+?)\s+fname=.+?sourceServiceName=(?!(SMTP|Endpoint Email))""",
    """\sduser=({external_address}[^\s;]+).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sduser=[^@]+@({external_domain}[^\s;]+).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sduser=({recipients}.+?)\s+(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=(N\/A|.*?[\/\\]*({file_name}[^\\\/]+))\s+\- [\d.]+ """,
    """\sfname=(N\/A|({attachment}.+?))\s+(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=.*\.({extension}[^\s]+)\s+(msg=|- ).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\smsg=({subject}.+?)\s+(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=(N\/A|.*?\.[^\s]+ - ({bytes_num}[\d.]+)\s+({bytes_unit}[^\s;]+))""",
    """\ssourceServiceName=({alert_type}.+?)\s\w+=""",
    """\|Websense\|(.+?\|){3}({alert_name}[^|]+)""",
    """\scat=({alert_name}[^;]+).*?\s+sourceService.+?analyzedBy""",
    """\|Websense\|(.+?\|){4}({alert_severity}[^|]+)""",
    """\sact=({outcome}[^\s]*)"""
  ]
}
```