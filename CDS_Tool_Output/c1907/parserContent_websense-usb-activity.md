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
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\sloginName=(({domain}[^\\]+)\\+)?({user}.+?)\s+(\w+=|$)""",
    """\sfname=(N\/A|({file_path}.*?[\/\\]+[^\\\/]+))\s+\- [\d.]+ """,
    """\sfname=(N\/A|.*?[\/\\]+({file_name}[^\\\/]+))\s+\- [\d.]+ """,
    """\smsg=({activity}.+?)\s+(\w+=|$)""",
    """\scat=({activity_details}.+?)\s+(\w+=|$)""",
    """\sfname=(N\/A|.*?[\/\\]+[^\\\/]+ - ({bytes_num}[\d.]+)\s+({bytes_unit}[^\s;]+))""",
    """\sduser=(?:|({device_id}.+?))\s+(\w+=|$)""",
    """({device_type}(USB|DVD|Removable Media))"""
  ]
}
```