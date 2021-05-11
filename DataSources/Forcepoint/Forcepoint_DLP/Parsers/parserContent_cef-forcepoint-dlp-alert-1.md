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
    """timeStamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wdvc=(N\/A|({host}[A-Fa-f:\d.]+))""",
    """\Wdvchost=(N\/A|({host}[\w\-.]+))""",
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """\Wact=({outcome}.+?)(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\Wduser=(N\/A|({target}[^\s;]+))""",
    """\Wduser=[^\s@]*?({top_domain}[^\/\.\s@]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s{1,100}\w+=""",
    """\Wfname=(N\/A|.*?[\/\\]*({file_name}[^\\\/=]+?))\s{1,100}\- [\d.]+ """,
    """\Wfname=(N\/A|.*? - ({bytes_num}[\d.]+)\s{1,100}({bytes_unit}[^\s;]+))""",
    """\Wfname=(N\/A|.*? - ({bytes_val}[\d.]+\s{1,100}[^\s;]+))""",
    """\Wmsg=\s{0,100}({additional_info}.+?)(\s{1,100}\-\s|\s{1,100}[\w\.]+=|$)""",
    """\Wcat=({alert_name}.+?)(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\WsourceServiceName=({alert_type}.+?)\s{1,100}(on |\w+=)""",
    """\WloginName=(N\/A|({user_fullname}[^@\(=\\]+?)\s{0,100}(\([^\)]+\)?)?(@({domain}[^@\s]+))?)(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\WloginName=(?:N\/A|(({domain}[^\\,]+)\\+)?({user}[^\\\s,]+))(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\Wsuser=(({domain}[^\\\s,@=]+)\\+)?({user}[^\\\s,@=]+)\s{1,100}(\w+=|$)""",
    """\Wsuser=(Executive Inquiry Mailbox|({user_fullname}[^\\\s,@=]+?\s{1,100}[^\\,@=]+?))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_lastname}[^\\,=]+?),\s{1,100}({user_firstname}[^\\,=]+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^\\\s,@=]+?@[^\\\s,@=]+?)\s{1,100}(\w+=|$)""",
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