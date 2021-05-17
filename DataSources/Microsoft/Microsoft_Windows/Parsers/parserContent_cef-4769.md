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
      """\srt=({time}\d{1,100})""",
      """\sduser=({user}.+?)(@({domain}.+?))?\s{1,100}\w+=""",
      """\sdestinationServiceName=({dest_host}\S+\$)\s""",
      """\sdestinationServiceName=({service_name}\S+)""",
      """\scs3=(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""",
      """\scs4=({result_code}[^\s]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """ncryption_,Type=({ticket_encryption_type}[^\s]{1,2000})""",
      """Ticket_,Options=({ticket_options}[^\s]{1,2000})"""
    ]
  }
```