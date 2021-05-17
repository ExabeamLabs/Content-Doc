#### Parser Content
```Java
{
Name = cef-673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-673"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Security:673|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}Account Logon)""",
    """({event_code}673)""",
    """\srt=({time}\d{1,100})""",
    """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\ssuser=({user}.+?)(@(.+?))?\s{1,100}\w+=""",
    """\ssuser=.+?(@({domain}.+?))?\s{1,100}\w+=""",
    """\sdestinationServiceName=({dest_host}\S+\$)\s""",
    """\sdestinationServiceName=({service_name}\S+)""",
    """\scs4=({result_code}[^\s]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """Ticket_,Options=({ticket_options}[^\s]{1,2000})""",
    """Ticket_,Encryption_,Type=({ticket_encryption_type}[^\s]{1,2000})"""
  ]
}
```