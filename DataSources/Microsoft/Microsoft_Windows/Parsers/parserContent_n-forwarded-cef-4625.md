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
      """\|McAfee\|[^|]+?\|[^|]+?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """\srt=({time}\d{1,100})""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s{1,100}\w+=""",
      """dst=(?:-|({dest_ip}[\w:.]+))\s{1,100}\w+=""",
      """src=(?:-|({src_ip}[\w:.]+))\s{1,100}\w+=""",
      """nitroAppID=({auth_package}[^\s]+)""",
      """nitroLogon_Type=({logon_type}\d{1,100})""",
      """nitroMessage_Text=({result_code}[^\s]+)\s{1,100}\w+="""
    ]
  }
```