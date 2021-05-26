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
    """\srt=({time}\d{1,100})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """\sduser=(({domain}[^\s]{1,2000}?)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssuser=({user}[^\s]{1,2000})""",
    """\sfname=({object}.+?)\s{0,100}(\w+=|$)""",
    """ad.Key\[1\]=({object}.+?)\s{0,100}ad\.Key""",
    """\sfsize=({bytes}\d{1,100})""",
    """ad.Key\[4\]=({printer_name}[^|]{0,2000}?)\s{0,100}(:?$|ad\.Key)""",
    """\scs2=({printer_name}.+?)\s{0,100}(\w+=|$).*cs2Label=Printer Name""",
    """ad.Key\[5\]=({printer_port}[^|]{0,2000}?)\s{0,100}(:?$|ad\.Key)""",
    """\scs3=({printer_port}.+?)\s{0,100}(\w+=|$).*cs3Label=Port""",
    """ad.Key\[7\]=({num_pages}\d{1,100})""",
    """\scn1=({num_pages}\d{1,100}).*cn1Label=Pages Printed""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdvc=({dest_ip}[^\s]{1,2000})""",
    """\sexternalId=({event_code}\d{1,100})""",
    """({activity}PrintService:307)""",
    """\smsg=({activity}.+?)\s{0,100}\w+="""
  ]
  DupFields = [ """host->dest_host""" ]
}
```