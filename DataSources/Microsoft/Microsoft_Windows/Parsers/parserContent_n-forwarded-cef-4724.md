#### Parser Content
```Java
{
Name = n-forwarded-cef-4724
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-password-reset"
    TimeFormat = "epoch"
    Conditions = [ "|McAfee|ESM", "43-26304724"]
    Fields = [ """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """({event_name}An attempt was made to reset an account's password)""",
      """\srt=({time}\d+)""",
      """shost=({host}[^\s]+)""",
      """sntdom=({domain}[^\s]+)""",
      """dntdom=({target_domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",
      """duser=({target_user}.+?)\s+\w+=""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)""",
      """nitroSecurity_ID=({user_sid}[^\s]+)""",
      """src=({src_ip}[A-Fa-f:\d.]+)""",
    ]
    DupFields=[ "host->dest_host" ]
  }
```