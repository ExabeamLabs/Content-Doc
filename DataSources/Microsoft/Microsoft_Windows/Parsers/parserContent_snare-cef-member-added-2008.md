#### Parser Content
```Java
{
Name = snare-cef-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-member-added"
  TimeFormat = "epoch"
  Conditions = [ """|IntersectAlliance|Snare|""", "A member was added to a security-enabled" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_code}\d{1,100})\|A member was added to a security-enabled""",
    """\|A member was added to a security-enabled ({group_type}\w+)""",
    """\srt=({time}\d{1,100})""",
    """\ssntdom=({domain}[^\s]+)""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssuid=({logon_id}\w+)""",
    """\sdntdom=({account_domain}[^\s]+)""",
    """\sduser=({account_id}.+?)\s{1,100}\w+=""",
    """\scs6=({group_domain}[^\\]+)""",
    """\scs6=.+?\\+({group_name}.+?)\s{1,100}\w+=""",
    """\sdvchost=({host}[^\s]+)""",
    """ad.Group:Security_,ID=({group_id}[^\s]+)""",
    """\sduid=(?=\w)({account_dn}.+?)\s{1,100}\w+=""",
    """\sduid=(?=\w)(.+?CN\\?=.+?,({account_ou}(OU)?.+?DC\\?=[\w-]+))\s\w+=""",
  ]
  DupFields = [ "host->dest_host" ]
}
```