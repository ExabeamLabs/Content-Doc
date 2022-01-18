#### Parser Content
```Java
{
Name = cef-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4770"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4770|""" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sdntdom=({domain}[^\s]{1,2000})""",
    """\sduser=({user}[^@]{1,2000})(@[^\s]{1,2000})?\s{1,100}\w+=""",
    """\sdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\scs3=(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\sdestinationServiceName =({service_name}\S+)""",
    """\sdestinationServiceName =({dest_host}\S+\$)""",
    """ncryption_,Type=({ticket_encryption_type}[^\s]{1,2000})""",
    """Ticket_,Options=({ticket_options}[^\s]{1,2000})"""
  ]


}
```