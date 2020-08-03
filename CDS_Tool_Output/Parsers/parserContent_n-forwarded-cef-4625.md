#### Parser Content
```Java
{
Name = n-forwarded-cef-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-failed-logon"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-26304625"]
    Fields = [
      """({event_name}An account failed to log on)""",
      """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """\srt=({time}\d+)""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",
      """dst=(?:-|({dest_ip}[\w:.]+))\s+\w+=""",
      """src=(?:-|({src_ip}[\w:.]+))\s+\w+=""",
      """nitroAppID=({auth_package}[^\s]+)""",
      """nitroLogon_Type=({logon_type}\d+)""",
      """nitroMessage_Text=({result_code}[^\s]+)\s+\w+="""
    ]
  }
```