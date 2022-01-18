#### Parser Content
```Java
{
Name = q-microsoft-4648
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-account-switch"
  TimeFormat = "epoch"
  Conditions = [ "EventIDCode=4648"]
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """EventIDCode=({event_code}\d{1,100})""",
    """\s{1,100}Computer=({host}[\w.\-]{1,2000})""",
    """Message=.+?\s({user}[^\s]{1,2000})\s({domain}[^\s]{1,2000})\s({login_id}[^\s]{1,2000})\s\{([^\}]{1,2000})\}\s({account}[^\s]{1,2000})\s({account_domain}[^\s]{1,2000})\s\{.*?\}\s({dest_service}[^\s]{1,2000})\w.*?\s.*?\s({process}[^\s]{1,2000})\\({process_name}[^\s]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```