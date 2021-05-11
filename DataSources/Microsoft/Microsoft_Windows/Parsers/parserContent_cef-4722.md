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
	      """\ssntdom=({domain}[^\s]+)""",
	      """\ssuser=({user}.+?)\s{1,100}\w+=""",
	      """\ssuid=({logon_id}[^\s]+)""",
	      """\sdntdom=({target_domain}[^\s]+)""",
	      """\sduser=({target_user}.+?)\s{1,100}\w+=""",
          """\sdvchost=({host}[^\s]+)""",
          """\sdhost=({dest_host}[^\s]+)""",
          """\sdst=({dest_ip}[a-fA-F:\d.]+)"""
    ]
  }
```