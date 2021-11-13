#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-alert-1
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ "|Forcepoint|Forcepoint DLP|", "sourceServiceName =" ]
  Fields = [
    """timeStamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wdvc=(N\/A|({host}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdvchost=(N\/A|({host}[\w\-.]{1,2000}))""",
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """\Wact=({outcome}.+?)(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\Wduser=(N\/A|({target}[^\s;]{1,2000}))""",
    """\sduser=({full_url}(\w+:\/+)?({web_domain}[^\\\/]{1,2000})[^\s]{1,2000})\s{1,100}\w+=""",
    """\Wfname=(N\/A|.*?[\/\\]{0,2000}({file_name}[^\\\/=]{1,2000}?))\s{1,100}\- [\d.]{1,2000} """,
    """\Wfname=(N\/A|.*? - ({bytes_num}[\d.]{1,2000})\s{1,100}({bytes_unit}[^\s;]{1,2000}))""",
    """\Wfname=(N\/A|.*? - ({bytes_val}[\d.]{1,2000}\s{1,100}[^\s;]{1,2000}))""",
    """\Wmsg=\s{0,100}({additional_info}.+?)(\s{1,100}\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\Wcat=({alert_name}.+?)(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\WsourceServiceName =({alert_type}.+?)\s{1,100}(on |\w+=)""",
    """\WloginName =(N\/A|({user_fullname}[^@\(=\\]{1,2000}?)\s{0,100}(\([^\)]{1,2000}\)?)?(@({domain}[^@\s]{1,2000}))?)(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\WloginName =(?:N\/A|(({domain}[^\\,]{1,2000})\\+)?({user}[^\\\s,]{1,2000}))(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\Wsuser=(({domain}[^\\\s,@=]{1,2000})\\+)?({user}[^\\\s,@=]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=(Executive Inquiry Mailbox|({user_fullname}[^\\\s,@=]{1,2000}?\s{1,100}[^\\,@=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_lastname}[^\\,=]{1,2000}?),\s{1,100}({user_firstname}[^\\,=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^\\\s,@=]{1,2000}?@[^\\\s,@=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WsourceIp=(?:N\/A|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\WseverityType=({alert_severity}[^\s]{1,2000})""",
    """\WsourceHost=(?:N\/A|({src_host}[\w\-.]{1,2000}))""",
    """\WdestinationHosts=(?:N\/A|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000})))""",
  ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity","file_name->dlpFileName", "bytes_val->dlpFileSize", "outcome->dlpActionTaken","host->dlpDeviceName"]
    NameTemplate = """Forcepoint DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```