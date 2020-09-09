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
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """({event_name}Account Logon)""",
    """({event_code}673)""",
    """\srt=({time}\d+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """\ssuser=({user}.+?)(@(.+?))?\s+\w+=""",
    """\ssuser=.+?(@({domain}.+?))?\s+\w+=""",
    """\sdestinationServiceName=({dest_host}\S+\$)\s""",
    """\sdestinationServiceName=({service_name}\S+)""",
    """\scs4=({result_code}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """Ticket_,Options=({ticket_options}[^\s]+)""",
    """Ticket_,Encryption_,Type=({ticket_encryption_type}[^\s]+)"""
  ]
}
```