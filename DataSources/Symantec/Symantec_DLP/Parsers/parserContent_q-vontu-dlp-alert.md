#### Parser Content
```Java
{
Name = q-vontu-dlp-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = QRadar
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """type=Vontu_""","""|lanid=""","""|rules=""" ]
    Fields = [
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}type=""",
      """\|incidentID=({alert_id}\d{1,100})""",
      """\|policy=({alert_name}[^|]+)\|""",
      """\|rules=({alert_type}[^|]+)\|""",
      """\|(src|suser)=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|((?!\w+[:@]+))({src_host}[^|\s]+))""",
      """\|(src|suser)=(?=[^\s@]+@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))({sender}[^|\s]+)""",
      """\|(src|suser)=({user}[^@|]+)@[^|]+""",
      """\|subject=(?:N\/A|({subject}[^|]+))""",
      """\|subject=(?=\s{0,100}FTP\s{0,100})\s{0,100}({protocol}FTP)\s{0,100}({file_name}[^|]+)""",
      """\|(dst|duser)=(?:N\/A|({target}[^|]+))""",
      """\|(dst|duser)=(?=\w+:\/)({protocol}.+?):\/+""",
      """\|(dst|duser)=({account}[^@]+)@({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\|(dst|duser)=(?=[^\s@]+@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))({recipients}[^|]+)""",
      """\|(dst|duser)=(?=[^\s@]+@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))({external_address}[^|,]+)""",
      """\|(dst|duser)=(?=[^\s@]+@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))(?:.+?@)({external_domain}[^|,]+)""",
      """\|endpoint=(?:N\/A|({src_host}[^$|\s]+))""",
      """\|fileName=(?:N\/A|({file_name}[^|]+))""",
      """\|fileName=(?=http(s)?:)({protocol}[^:|]+)""",
      """\stype=({additional_info}[^|]+)""",
      """\|blocked=({outcome}[^|]+)"""
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "protocol->dlpProtocol", "src_host->dlpDeviceName", "file_name->dlpFileName", "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```