#### Parser Content
```Java
{
Name = cef-4740
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-account-lockout"
    TimeFormat = "epoch"
    Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4740|""" ]
    Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
      """({event_name}A user account was locked out)""",
      """\sexternalId=({event_code}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sshost=({src_host}[^\s]{1,2000})""",
      """\ssrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
      """\ssntdom=({caller_domain}[^\s]{1,2000})""",
      """\ssuser=({caller_user}.+?)\s{1,100}\w+=""",
      """\sdntdom=({domain}[^\s]{1,2000})""",
      """\sduser=({user}.+?)\s{1,100}\w+=""",
      """\sduid=({logon_id}[^\s]{1,2000})""",
      """\sdvc=({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})"""
    ]
    DupFields = [ "host->dest_host" ]
  

}
```