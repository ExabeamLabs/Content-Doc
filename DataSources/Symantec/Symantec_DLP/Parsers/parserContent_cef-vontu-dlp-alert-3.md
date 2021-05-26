#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert-3
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    Conditions = [ """CEF:""", """Symantec|DLP""","""POLICY=""", """MONITOR_NAME=""", """APPLICATION_NAME=""" ]
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({host}\S+)\s{1,100}CEF:""",
      """\WINCIDENT_ID=({alert_id}\d{1,100})""",
      """\WPOLICY=({alert_name}[^=]{1,2000})\s\w+=""",
      """\WSEVERITY=\d{1,100}:({alert_severity}[^=]{1,2000})\s\w+=""",
      """\WPROTOCOL=({protocol}[^=]{1,2000})\s\w+=""",
      """\WBLOCKED=(None|({outcome}[^=]{1,2000}))\s\w+=""",
      """\WSENDER=({src_ip}[A-Fa-f.:\d]{1,2000})\s{1,100}\w+=""",
      """\WENDPOINT_MACHINE=(N\/A|({src_host}[^=]{1,2000}))\s\w+="""
      """\WRECIPIENTS=(N\/A|({target}[^=]{1,2000}))\s\w+=""",
      """\WRECIPIENTS=(N\/A|({recipients}[^@]{1,2000}@[^=]{1,2000}))\s\w+=""",
      """\WSUBJECT=+\s{0,100}(N\/A|({subject}[^=]{1,2000}))\s\w+=""",
      """\WATTACHMENT_FILENAME=\s{0,100}(N\/A|({file_name}[^=]{1,2000}?))\s{0,100}\w+=""",
      """\WSENDER=((WinNT:\/+({domain}[^\/]{1,2000})\/({user}[^=]{1,2000}))|({user_email}[^@]{1,2000}@[^=]{1,2000}))\s\w+=""",
    ]
    DupFields = [ "subject->additional_info" , "user_email->sender"]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="user", Name="windows_id", Fields=["user->windows_id"]}
```