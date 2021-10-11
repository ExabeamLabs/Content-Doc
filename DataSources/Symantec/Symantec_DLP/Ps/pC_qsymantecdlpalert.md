#### Parser Content
```Java
{
Name = q-symantec-dlp-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Conditions = [ """Symantec|DLP|""", """|policy=""", """|incidentSnapshot=""" ]
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|occurredon=({time}\w+ \d{1,100}, \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \w+)\|""",
    """({host}[\w.\-]{1,2000})\s{1,100}Symantec\|DLP\|""",
    """\|severity=({alert_severity}[^\|]{1,2000})""",
    """\|policy=({alert_name}[^\|]{1,2000})""",
    """\|policy=([^-\|]{0,2000}\-)?\s{0,100}({alert_type}[^\|]{1,2000})""",
    """\|rules=({rules}[^\|]{1,2000})""",
    """\|action=(None|({outcome}[^\|]{1,2000}))""",
    """\|incidentID=({alert_id}\d{1,100})""",
    """\|protocol=({protocol}[^\|]{1,2000}?)\s{0,100}(\||$)""",
    """\|subject=((?!SFTP|HTTP|FTP|TCP|N\/A)({subject}[^\|]{1,2000}))""",
    """\|fileName=(?!https:|N\/A).*?({file_name}[^\|]{1,2000})""",
    """\|AttachmentName=(N\/A|({file_name}[^\|]{1,2000}?))\s{0,100}(\||$)""",
    """\|endpointusrname=(N\/A|(({domain}[^\\]{1,2000})\\+)?({user}[^\s\|]{1,2000}))""",
    """\|Username=(N\/A|(({domain}[^\\\|]{1,2000})\\+)?({user}[^\s\|]{1,2000}))""",
    """\|subject.*?\|Username=(N\/A|(({domain}[^\\]{1,2000})\\+)?({user}[^\s\|]{1,2000}))""",
    """\|(Username|src)=({user}[^\s@\|]{1,2000}@[^@\s\|]{1,2000})""",
    """\|(Username|src)=WinNT:\/+({domain}[^\\\/\|]{1,2000})(\\|\/)+({user}[^\s\|]{1,2000})""",
    """\|endpointhostname=(N\/A|({src_host}[\w\-.]{1,2000}))""",
    """\|endpointipaddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|sender=(?=[\w.]{1,2000}@[\w.])({sender}[^\|]{1,2000})""",
    """\|sender=(?=[\w.]{1,2000}@[\w.])({user}[^\|]{1,2000})""",
    """\|EmailAddress=({user_email}[^\|]{1,2000}?)\s{0,100}(\||$)""",
    """\|recipients=({target}[^\|]{1,2000}?)\s{0,100}(\||$)""",
    """\|destination=({target}[^\|]{1,2000}?)\s{0,100}(\||$)""",
    """\|incidentSnapshot=\w+:\/+[^\s]{0,2000}?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\|)""",
    """\|matchCount=({match_count}[^\|]{1,2000}?)\s{0,100}(\||$)""",
  ]
  DupFields = [ "protocol->alert_type" ]
  SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "file_name->dlpFileName",  "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address","dest_host->host_name"]}
```