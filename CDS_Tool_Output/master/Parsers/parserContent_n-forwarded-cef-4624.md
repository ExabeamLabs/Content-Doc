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
    Fields = ["""\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """({event_name}An account was successfully logged on)""",
      """\srt=({time}\d+)""",
      """shost=({host}[^\s]+)""",
      """src=(?:-|({src_ip}[\w:.]+))\s+\w+=""",
      """nitroAppID=({auth_package}.+?)\s+\w+=""",
      """sntdom=({domain}.+?)\s+\w+=""",
      """suser=({user}.+?)\s+\w+=""",
      """duser=({user}.+?)\s+\w+=""",
      """nitroLogon_Type=({logon_type}\d+)""",
      """nitroDestination_Logon_ID=({logon_id}.+?)(\s|0\||\))"""
    ]
    DupFields = ["host->dest_host"]
  }
```