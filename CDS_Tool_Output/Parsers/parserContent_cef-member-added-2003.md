#### Parser Content
```Java
{
Name = cef-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-member-added"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""", """|Security:6""", """Security Enabled""", """Group Member Added""" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]+ Group Member Added)""",
    """exabeam_EventTime=({eventtime}\d+)""",
    """Security:({event_code}\d+)""",
    """\|Security Enabled ({group_type}\w+)""",
    """\srt=({time}\d+)""",
    """\ssntdom=({domain}[^\s]+)""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\ssuid=\([^,]+,({logon_id}[^\)]+)""",
    """\sdntdom=({group_domain}[^\s]+)""",
    """duser=({group_name}.+?)\s+\w+=""",
    """\scs6=({account_dn}.+?)\s+\w+=""",
    """\scs6=(.+?CN\\?=.+?,({account_ou}(OU)?.+?DC\\?=[\w-]+))\s\w+=""",
    """\sdvchost=({host}[^\s]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```