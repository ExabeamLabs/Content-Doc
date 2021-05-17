#### Parser Content
```Java
{
Name = n-forwarded-cef-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-4624"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-26304624"]
    Fields = ["""\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """({event_name}An account was successfully logged on)""",
      """\srt=({time}\d{1,100})""",
      """shost=({host}[^\s]{1,2000})""",
      """src=(?:-|({src_ip}[\w:.]{1,2000}))\s{1,100}\w+=""",
      """nitroAppID=({auth_package}.+?)\s{1,100}\w+=""",
      """sntdom=({domain}.+?)\s{1,100}\w+=""",
      """suser=({user}.+?)\s{1,100}\w+=""",
      """duser=({user}.+?)\s{1,100}\w+=""",
      """nitroLogon_Type=({logon_type}\d{1,100})""",
      """nitroDestination_Logon_ID=({logon_id}.+?)(\s|0\||\))"""
    ]
    DupFields = ["host->dest_host"]
  }
```