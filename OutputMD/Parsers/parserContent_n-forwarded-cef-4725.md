#### Parser Content
```Java
{
Name = n-forwarded-cef-4725
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-account-disabled"
    TimeFormat = "epoch"
    Conditions = [ "|McAfee|ESM", "43-26304725"]
    Fields = [ """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """({event_name}A user account was disabled)""",
      """\srt=({time}\d+)""",
      """shost=({host}[^\s]+)""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",
      """duser=({target_user}.+?)\s+\w+=""",
      """nitroSource_Logon_ID=({logon_id}[^\s]+)""",
      """nitroSecurity_ID=({user_sid}[^\s]+)"""
    ]
    DupFields=[ "host->dest_host" ]
  }
```