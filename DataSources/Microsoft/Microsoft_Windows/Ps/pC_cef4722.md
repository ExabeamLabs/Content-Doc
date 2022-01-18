#### Parser Content
```Java
{
Name = cef-4722
	    Vendor = Microsoft
            Product = Microsoft Windows
	    Lms = ArcSight
	    DataType = "windows-account-enabled"
	    TimeFormat = "epoch"
	    Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4722""" ]
	    Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
	      """({event_name}A user account was enabled)""",
	      """\sexternalId=({event_code}\d{1,100})""",
	      """\srt=({time}\d{1,100})""",
	      """\ssntdom=({domain}[^\s]{1,2000})""",
	      """\ssuser=({user}.+?)\s{1,100}\w+=""",
	      """\ssuid=({logon_id}[^\s]{1,2000})""",
	      """\sdntdom=({target_domain}[^\s]{1,2000})""",
	      """\sduser=({target_user}.+?)\s{1,100}\w+=""",
          """\sdvchost=({host}[^\s]{1,2000})""",
          """\sdhost=({dest_host}[^\s]{1,2000})""",
          """\sdst=({dest_ip}[a-fA-F:\d.]{1,2000})"""
    ]
  

}
```