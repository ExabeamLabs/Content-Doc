#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert-2
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    Conditions = [ """Symantec|DLP""","""POLICY=""" ]
    TimeFormat = "MMM dd, yyyy HH:mm:ss a"
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """OCCURRED_ON=({time}\w+\s+\d+,\s*\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))""",
      """exabeam_host=({host}[^\s]+)""",
      """({host}\S+)\s+\|?Symantec\|DLP""",
      """INCIDENT=({alert_id}\d+)\|""",
      """\|\s*POLICY=({alert_name}[^\|]+)""",
      """\|\s*SEVERITY=({alert_severity}[^\|]+)""",
      """\|\s*PROTOCOL=({protocol}[^\|]+)""",
      """\|\s*BLOCKED=(None|({outcome}\w+))""",
      """\|\s*SENDER=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\|\s*ENDPOINT_USERNAME=(N\/A|(({domain}[^\s\\\|@]+)\\+)?({user}[^\s\\\|@]+))\|""",
      """\|\s*SENDER=(N\/A|({user_email}[^\\\s\|@]+@[^\\\s\|]+))\|""",
      """\|\s*RECIPIENTS=+(N\/A|({target}[^\|]+))""",
      """\|\s*SUBJECT=+\s*(N\/A|({subject}[^\|]+?))\s*\|""",
      """\|\s*ATTACHMENTS=({file_name}[^\|]+?)\s*(\||$)"""
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