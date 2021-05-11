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
      """exabeam_host=({host}[^\s]+)""",
      """({host}\S+)\s{1,100}CEF:""",
      """\WINCIDENT_ID=({alert_id}\d{1,100})""",
      """\WPOLICY=({alert_name}[^=]+)\s\w+=""",
      """\WSEVERITY=\d{1,100}:({alert_severity}[^=]+)\s\w+=""",
      """\WPROTOCOL=({protocol}[^=]+)\s\w+=""",
      """\WBLOCKED=(None|({outcome}[^=]+))\s\w+=""",
      """\WSENDER=({src_ip}[A-Fa-f.:\d]+)\s{1,100}\w+=""",
      """\WENDPOINT_MACHINE=(N\/A|({src_host}[^=]+))\s\w+="""
      """\WRECIPIENTS=(N\/A|({target}[^=]+))\s\w+=""",
      """\WRECIPIENTS=(N\/A|({recipients}[^@]+@[^=]+))\s\w+=""",
      """\WSUBJECT=+\s{0,100}(N\/A|({subject}[^=]+))\s\w+=""",
      """\WATTACHMENT_FILENAME=\s{0,100}(N\/A|({file_name}[^=]+?))\s{0,100}\w+=""",
      """\WSENDER=((WinNT:\/+({domain}[^\/]+)\/({user}[^=]+))|({user_email}[^@]+@[^=]+))\s\w+=""",
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