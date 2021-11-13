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
      """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}type=""",
      """\|incidentID=({alert_id}\d{1,100})""",
      """\|policy=({alert_name}[^|]{1,2000})\|""",
      """\|rules=({alert_type}[^|]{1,2000})\|""",
      """\|(src|suser)=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|((?!\w+[:@]{1,2000}))({src_host}[^|\s]{1,2000}))""",
      """\|(src|suser)=(?=[^\s@]{1,2000}@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))({sender}[^|\s]{1,2000})""",
      """\|(src|suser)=({user}[^@|]{1,2000})@[^|]{1,2000}""",
      """\|subject=(?:N\/A|({subject}[^|]{1,2000}))""",
      """\|subject=(?=\s{0,100}FTP\s{0,100})\s{0,100}({protocol}FTP)\s{0,100}({file_name}[^|]{1,2000})""",
      """\|(dst|duser)=(?:N\/A|({target}[^|]{1,2000}))""",
      """\|(dst|duser)=(?=\w+:\/)({protocol}.+?):\/+""",
      """\|(dst|duser)=({account}[^@]{1,2000})@({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\|(dst|duser)=(?=[^\s@]{1,2000}@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))({recipients}[^|]{1,2000})""",
      """\|(dst|duser)=(?=[^\s@]{1,2000}@(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))({external_address}[^|,]{1,2000})""",
      """\|endpoint=(?:N\/A|({src_host}[^$|\s]{1,2000}))""",
      """\|fileName =(?:N\/A|({file_name}[^|]{1,2000}))""",
      """\|fileName =(?=http(s)?:)({protocol}[^:|]{1,2000})""",
      """\stype=({additional_info}[^|]{1,2000})""",
      """\|blocked=({outcome}[^|]{1,2000})"""
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "protocol->dlpProtocol", "src_host->dlpDeviceName", "file_name->dlpFileName", "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```