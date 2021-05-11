#### Parser Content
```Java
{
Name = s-dlp-email-out
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CEF:","|Websense|Data Security", "sourceServiceName=" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\sloginName=(({domain}[^\\]+)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """sourceServiceName=(SMTP|Endpoint Email).+?suser=([^\\]+\\+)?({sender}.+?)\s{1,100}(\w+=|$)""",
    """sourceServiceName=(SMTP|Endpoint Email).+?loginName=([^\\]+\\+)?({sender}.+?)\s{1,100}(\w+=|$)""",
    """\sduser=\\*(({target_domain}[^\\]+)\\+)?({target}.+?)\s{1,100}fname=.+?sourceServiceName=(?!(SMTP|Endpoint Email))""",
    """\sduser=({external_address}[^\s;]+).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sduser=[^@]+@({external_domain}[^\s;]+).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sduser=({recipients}.+?)\s{1,100}(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=(N\/A|.*?[\/\\]*({file_name}[^\\\/]+))\s{1,100}\- [\d.]+ """,
    """\sfname=(N\/A|({attachment}.+?))\s{1,100}(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=.*\.({extension}[^\s]+)\s{1,100}(msg=|- ).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\smsg=({subject}.+?)\s{1,100}(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=(N\/A|.*?\.[^\s]+ - ({bytes_num}[\d.]+)\s{1,100}({bytes_unit}[^\s;]+))""",
    """\ssourceServiceName=({alert_type}.+?)\s\w+=""",
    """\|Websense\|([^|]+?\|){3}({alert_name}[^|]+)""",
    """\scat=({alert_name}[^;]+).*?\s{1,100}sourceService.+?analyzedBy""",
    """\|Websense\|([^|]+?\|){4}({alert_severity}[^|]+)""",
    """\sact=({outcome}[^\s]*)"""
  ]
}
```