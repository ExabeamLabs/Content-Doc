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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\s{1,100}Computer=({dest_host}[\w.\-]{1,2000})""",
    """exabeam_endTime=({time}\d{1,100})""",
    """EventIDCode=({event_code}\d{1,100})""",
    """Message=({user}[^\s]{1,2000})\s({src_host}[^\s]{1,2000})\s({user_sid}[^\s]{1,2000})\s(.+?)\s({caller_user}[^\s]{1,2000})\s({caller_domain}[^\s]{1,2000})\s({logon_id}[^\s]{1,2000})\s{0,100}$"""
  ]
  DupFields = ["caller_domain->domain"]


}
```