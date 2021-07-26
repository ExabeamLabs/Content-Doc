#### Parser Content
```Java
{
Name = websense-usb-activity
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CEF:","|Websense|Data Security", "sourceServiceName=Endpoint Removable Media", "act=Permitted" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\sloginName=(({domain}[^\\]{1,2000})\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\sfname=(N\/A|({file_path}.*?[\/\\]{1,2000}[^\\\/]{1,2000}))\s{1,100}\- [\d.]{1,2000} """,
    """\sfname=(N\/A|.*?[\/\\]{1,2000}({file_name}[^\\\/]{1,2000}))\s{1,100}\- [\d.]{1,2000} """,
    """\smsg=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\scat=({activity_details}.+?)\s{1,100}(\w+=|$)""",
    """\sfname=(N\/A|.*?[\/\\]{1,2000}[^\\\/]{1,2000} - ({bytes_num}[\d.]{1,2000})\s{1,100}({bytes_unit}[^\s;]{1,2000}))""",
    """\sduser=(?:|({device_id}.+?))\s{1,100}(\w+=|$)""",
    """({device_type}(USB|DVD|Removable Media))"""
  ]
}
```