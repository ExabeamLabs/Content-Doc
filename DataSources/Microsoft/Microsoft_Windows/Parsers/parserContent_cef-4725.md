#### Parser Content
```Java
{
Name = cef-4725
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-account-disabled"
    TimeFormat = "epoch"
    Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4725|""" ]
    Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
      """({event_name}A user account was disabled)""",
      """\sexternalId=({event_code}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}[a-fA-F:\d.]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sdhost=({dest_host}[^\s]{1,2000})""",
      """\sdst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",
      """\ssntdom=({domain}.+?)\s\w+=""",
      """\ssuid=({logon_id}[^\s]{1,2000})""",
      """\sduser=({target_user}.+?)\s{1,100}\w+=""",
      """\sdntdom=({target_domain}.+?)\s\w+=""",
      """Security_,ID=({target_user_sid}[^\s]{1,2000})"""
    ]
  }
```