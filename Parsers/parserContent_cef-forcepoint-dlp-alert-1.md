#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-alert-1
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ "|Forcepoint|Forcepoint DLP|", "sourceServiceName=" ]
  Fields = [
    """timeStamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wdvc=(N\/A|({host}[A-Fa-f:\d.]+))""",
    """\Wdvchost=(N\/A|({host}[\w\-.]+))""",
    """({host}[\w\-.]+)\s+CEF:""",
    """\Wact=({outcome}.+?)(\s\-\s|\s+[\w\.]+=|$)""",
    """\Wduser=(N\/A|({target}[^\s;]+))""",
    """\Wduser=[^\s@]*?({top_domain}[^\/\.\s@]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s+\w+=""",
    """\Wfname=(N\/A|.*?[\/\\]*({file_name}[^\\\/=]+?))\s+\- [\d.]+ """,
    """\Wfname=(N\/A|.*? - ({bytes_num}[\d.]+)\s+({bytes_unit}[^\s;]+))""",
    """\Wfname=(N\/A|.*? - ({bytes_val}[\d.]+\s+[^\s;]+))""",
    """\Wmsg=\s*({additional_info}.+?)(\s+\-\s|\s+[\w\.]+=|$)""",
    """\Wcat=({alert_name}.+?)(\s\-\s|\s+[\w\.]+=|$)""",
    """\WsourceServiceName=({alert_type}.+?)\s+(on |\w+=)""",
    """\WloginName=(N\/A|({user_fullname}[^@\(=\\]+?)\s*(\([^\)]+\)?)?(@({domain}[^@\s]+))?)(\s\-\s|\s+[\w\.]+=|$)""",
    """\WloginName=(?:N\/A|(({domain}[^\\,]+)\\+)?({user}[^\\\s,]+))(\s\-\s|\s+[\w\.]+=|$)""",
    """\WsourceIp=(?:N\/A|({src_ip}[A-Fa-f:\d.]+))""",
    """\WseverityType=({alert_severity}[^\s]+)""",
    """\WsourceHost=(?:N\/A|({src_host}[\w\-.]+))""",
    """\WdestinationHosts=(?:N\/A|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+)))""",
  ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity","file_name->dlpFileName", "bytes_val->dlpFileSize", "outcome->dlpActionTaken","host->dlpDeviceName"]
    NameTemplate = """Forcepoint DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```