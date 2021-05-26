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
    Fields = [ """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """({event_name}An attempt was made to reset an account's password)""",
      """\srt=({time}\d{1,100})""",
      """shost=({host}[^\s]{1,2000})""",
      """sntdom=({domain}[^\s]{1,2000})""",
      """dntdom=({target_domain}[^\s]{1,2000})""",
      """suser=({user}.+?)\s{1,100}\w+=""",
      """duser=({target_user}.+?)\s{1,100}\w+=""",
      """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)""",
      """nitroSecurity_ID=({user_sid}[^\s]{1,2000})""",
      """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    ]
    DupFields=[ "host->dest_host" ]
  }
```