#### Parser Content
```Java
{
Name = cef-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-member-added"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""", "A member was added to a security-enabled" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_code}\d{1,100})\|A member was added to a security-enabled""",
    """\|A member was added to a security-enabled ({group_type}\w+)""",
    """\srt=({time}\d{1,100})""",
    """\ssntdom=({domain}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssuid=({logon_id}\w+)""",
    """\sdntdom=({account_domain}[^\s]{1,2000})""",
    """\sduser=({account_id}.+?)\s{1,100}\w+=""",
    """\scs6=({group_domain}[^\\]{1,2000})""",
    """\scs6=[^=]{1,2000}?\\{1,25}({group_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """ad.Group:Security_,ID=({group_id}[^\s]{1,2000})""",
    """\sduid=(?=\w)({account_dn}.+?)\s{1,100}\w+=""",
    """\sduid=(?=\w)(.+?CN\\?=.+?,({account_ou}(OU)?.+?DC\\?=[\w-]{1,2000}))\s\w+=""",
  ]
  DupFields = [ "host->dest_host" ]
}
```