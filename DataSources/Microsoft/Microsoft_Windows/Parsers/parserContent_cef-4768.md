#### Parser Content
```Java
{
Name = cef-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-4768"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4768"""]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({event_code}4768)""",
      """\srt=({time}\d{1,100})""",
      """\sduser=({user}[^\s]+)""",
      """\scs3=(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """\scs4=({result_code}\w+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sdntdom=({domain}[^\s]+)""",
      """Service_,ID=({user_sid}[^\s]+)\s""",
      """\sdestinationServiceName=({service_name}\S+)""",
      """ncryption_,Type=({ticket_encryption_type}[^\s]+)""",
      """Ticket_,Options=({ticket_options}[^\s]+)"""
    ]
    DupFields = ["host->dest_host"]
  }
```