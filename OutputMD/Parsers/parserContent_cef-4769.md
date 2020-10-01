#### Parser Content
```Java
{
Name = cef-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-4769"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4769"""]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """({event_code}4769)""",
      """\srt=({time}\d+)""",
      """\sduser=({user}.+?)(@({domain}.+?))?\s+\w+=""",
      """\sdestinationServiceName=({dest_host}\S+\$)\s""",
      """\sdestinationServiceName=({service_name}\S+)""",
      """\scs3=(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """\scs4=({result_code}[^\s]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """ncryption_,Type=({ticket_encryption_type}[^\s]+)""",
      """Ticket_,Options=({ticket_options}[^\s]+)"""
    ]
  }
```