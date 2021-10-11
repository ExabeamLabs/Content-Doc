#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert-2
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    Conditions = [ """Symantec|DLP""","""POLICY=""" ]
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """OCCURRED_ON=({time}\w+\s{1,100}\d{1,100},\s{0,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({host}\S+)\s{1,100}\|?Symantec\|DLP""",
      """INCIDENT=({alert_id}\d{1,100})\|""",
      """\|\s{0,100}POLICY=({alert_name}[^\|]{1,2000})""",
      """\|\s{0,100}SEVERITY=({alert_severity}[^\|]{1,2000})""",
      """\|\s{0,100}PROTOCOL=({protocol}[^\|]{1,2000})""",
      """\|\s{0,100}BLOCKED=(None|({outcome}\w+))""",
      """\|\s{0,100}SENDER=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\|\s{0,100}ENDPOINT_USERNAME=(N\/A|(({domain}[^\s\\\|@]{1,2000})\\+)?({user}[^\s\\\|@]{1,2000}))\|""",
      """\|\s{0,100}SENDER=(N\/A|({user_email}[^\\\s\|@]{1,2000}@[^\\\s\|]{1,2000}))\|""",
      """\|\s{0,100}RECIPIENTS=+(N\/A|({target}[^\|]{1,2000}))""",
      """\|\s{0,100}SUBJECT=+\s{0,100}(N\/A|({subject}[^\|]{1,2000}?))\s{0,100}\|""",
      """\|\s{0,100}ATTACHMENTS=({file_name}[^\|]{1,2000}?)\s{0,100}(\||$)"""
    ]
    DupFields = [ "subject->additional_info" , "user_email->sender", "target->recipients"]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="user", Name="windows_id", Fields=["user->windows_id"]}
```