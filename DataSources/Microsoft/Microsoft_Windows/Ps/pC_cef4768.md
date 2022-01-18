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
      """\sduser=({user}[^\s]{1,2000})""",
      """\scs3=(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """\scs4=({result_code}\w+)""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sdntdom=({domain}[^\s]{1,2000})""",
      """Service_,ID=({user_sid}[^\s]{1,2000})\s""",
      """\sdestinationServiceName =({service_name}\S+)""",
      """ncryption_,Type=({ticket_encryption_type}[^\s]{1,2000})""",
      """Ticket_,Options=({ticket_options}[^\s]{1,2000})"""
    ]
    DupFields = ["host->dest_host"]
  

}
```