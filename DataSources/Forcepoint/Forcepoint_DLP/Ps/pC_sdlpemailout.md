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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\sloginName=(({domain}[^\\]{1,2000})\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """sourceServiceName=(SMTP|Endpoint Email).+?suser=([^\\]{1,2000}\\+)?({sender}.+?)\s{1,100}(\w+=|$)""",
    """sourceServiceName=(SMTP|Endpoint Email).+?loginName=([^\\]{1,2000}\\+)?({sender}.+?)\s{1,100}(\w+=|$)""",
    """\sduser=\\*(({target_domain}[^\\]{1,2000})\\+)?({target}.+?)\s{1,100}fname=.+?sourceServiceName=(?!(SMTP|Endpoint Email))""",
    """\sduser=({external_address}[^\s;]{1,2000}).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sduser=[^@]{1,2000}@({external_domain}[^\s;]{1,2000}).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sduser=({recipients}.+?)\s{1,100}(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=(N\/A|.*?[\/\\]{0,2000}({file_name}[^\\\/]{1,2000}))\s{1,100}\- [\d.]{1,2000} """,
    """\sfname=(N\/A|({attachment}.+?))\s{1,100}(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=.*\.({extension}[^\s]{1,2000})\s{1,100}(msg=|- ).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\smsg=({subject}.+?)\s{1,100}(\w+=|$).+?sourceServiceName=(SMTP|Endpoint Email)""",
    """\sfname=(N\/A|.*?\.[^\s]{1,2000} - ({bytes_num}[\d.]{1,2000})\s{1,100}({bytes_unit}[^\s;]{1,2000}))""",
    """\ssourceServiceName=({alert_type}.+?)\s\w+=""",
    """\|Websense\|([^|]{1,2000}?\|){3}({alert_name}[^|]{1,2000})""",
    """\scat=({alert_name}[^;]{1,2000}).*?\s{1,100}sourceService.+?analyzedBy""",
    """\|Websense\|([^|]{1,2000}?\|){4}({alert_severity}[^|]{1,2000})""",
    """\sact=({outcome}[^\s]{0,2000})"""
  ]
}
```