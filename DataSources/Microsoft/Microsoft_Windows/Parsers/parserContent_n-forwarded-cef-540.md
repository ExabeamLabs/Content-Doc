#### Parser Content
```Java
{
Name = n-forwarded-cef-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-540"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "43-21100540"]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """\|McAfee\|[^|]+?\|[^|]+?\|43-21100({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})""",
    """shost=({host}[^\s]+)""",
    """src=(?:-|({src_ip}[\w:.]+))\s{1,100}\w+=""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}.+?)\s{1,100}nitro[\w]+=""",
    """nitroLogon_Type=({logon_type}\d{1,100})""",
    """nitroDestination_Logon_ID=\([^,]+,({logon_id}[^\)]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```