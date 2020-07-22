#### Parser Content
```Java
{
Name = cef-microsoft-print-activity
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = NitroCefSyslog
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft-Windows-PrintService:307|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sshost=({src_host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\sduser=(({domain}[^\s]+?)\\+)?({user}.+?)\s+(\w+=|$)""",
    """\ssuser=({user}[^\s]+)""",
    """\sfname=({object}.+?)\s*(\w+=|$)""",
    """ad.Key\[1\]=({object}.+?)\s*ad\.Key""",
    """\sfsize=({bytes}\d+)""",
    """ad.Key\[4\]=({printer_name}[^|]*?)\s*(:?$|ad\.Key)""",
    """\scs2=({printer_name}.+?)\s*(\w+=|$).*cs2Label=Printer Name""",
    """ad.Key\[5\]=({printer_port}[^|]*?)\s*(:?$|ad\.Key)""",
    """\scs3=({printer_port}.+?)\s*(\w+=|$).*cs3Label=Port""",
    """ad.Key\[7\]=({num_pages}\d+)""",
    """\scn1=({num_pages}\d+).*cn1Label=Pages Printed""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdvc=({dest_ip}[^\s]+)""",
    """\sexternalId=({event_code}\d+)""",
    """({activity}PrintService:307)""",
    """\smsg=({activity}.+?)\s*\w+="""
  ]
  DupFields = [ """host->dest_host""" ]
}
```