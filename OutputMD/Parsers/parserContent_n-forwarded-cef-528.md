#### Parser Content
```Java
{
Name = n-forwarded-cef-528
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-528"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "43-21100528" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """\|McAfee\|.+?\|43-21100({event_code}\d+)(0|1)\|""",
    """\srt=({time}\d+)""",
    """shost=({host}[^\s]+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}.+?)\s+nitro[\w]+=""",
    """nitroLogon_Type=({logon_type}\d+)""",
    """nitroDestination_Logon_ID=\([^,]+,({logon_id}[^\)]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```