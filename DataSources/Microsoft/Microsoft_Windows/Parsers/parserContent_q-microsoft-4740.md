#### Parser Content
```Java
{
Name = q-microsoft-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-account-lockout"
  TimeFormat = "epoch"
  Conditions = [ "EventIDCode=4740"]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\s{1,100}Computer=({dest_host}[\w.\-]+)""",
    """exabeam_endTime=({time}\d{1,100})""",
    """EventIDCode=({event_code}\d{1,100})""",
    """Message=({user}[^\s]+)\s({src_host}[^\s]+)\s({user_sid}[^\s]+)\s(.+?)\s({caller_user}[^\s]+)\s({caller_domain}[^\s]+)\s({logon_id}[^\s]+)\s{0,100}$"""
  ]
  DupFields = ["caller_domain->domain"]
}
```